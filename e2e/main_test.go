package e2e

import (
	"encoding/json"
	"math/rand"
	"testing"
	"time"

	"github.com/CosmWasm/wasmd/x/wasm/keeper"
	"github.com/babylonlabs-io/babylon/v3/app"
	"github.com/babylonlabs-io/babylon/v3/app/signingcontext"
	"github.com/babylonlabs-io/babylon/v3/crypto/eots"
	"github.com/babylonlabs-io/babylon/v3/testutil/datagen"
	bbn "github.com/babylonlabs-io/babylon/v3/types"
	bstypes "github.com/babylonlabs-io/babylon/v3/x/btcstaking/types"
	ckpttypes "github.com/babylonlabs-io/babylon/v3/x/checkpointing/types"
	etypes "github.com/babylonlabs-io/babylon/v3/x/epoching/types"
	ftypes "github.com/babylonlabs-io/babylon/v3/x/finality/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	pathToContract = "../artifacts/finality.wasm"
)

var (
	r             = rand.New(rand.NewSource(time.Now().UnixNano()))
	fpSK, fpPK, _ = datagen.GenRandomBTCKeyPair(r)
	randListInfo  *datagen.RandListInfo
)

func TestFinalityContractTestSuite(t *testing.T) {
	suite.Run(t, new(FinalityContractTestSuite))
}

type FinalityContractTestSuite struct {
	suite.Suite

	ctx          sdk.Context
	babylonApp   *app.BabylonApp
	contractCfg  *Config
	owner        sdk.AccAddress
	contractAddr sdk.AccAddress
}

func (s *FinalityContractTestSuite) SetupSuite() {
	// Initialize app and context
	s.babylonApp, s.ctx = SetupAppWithContext(s.T())

	// Create and fund test account
	s.owner = RandomAccountAddress()
	FundAccount(s.T(), s.ctx, s.babylonApp, s.owner)

	// Deploy contracts
	s.contractAddr = s.deployContracts(
		s.owner,
		pathToContract,
	)

	require.NotEmpty(s.T(), s.contractAddr)
}

func (s *FinalityContractTestSuite) Test1RegisterRollupBSN() {
	// register BSN
	bsn := datagen.GenRandomRollupRegister(r, s.contractAddr.String())
	bsn.ConsumerId = s.contractCfg.BsnID
	err := s.babylonApp.BTCStkConsumerKeeper.RegisterConsumer(s.ctx, bsn)
	s.NoError(err)

	// ensure BSN is registered
	bsnInDB, err := s.babylonApp.BTCStkConsumerKeeper.GetConsumerRegister(s.ctx, s.contractCfg.BsnID)
	s.NoError(err)
	s.Equal(bsn.ConsumerId, bsnInDB.ConsumerId)
	s.Equal(bsn.ConsumerDescription, bsnInDB.ConsumerDescription)
	s.Equal(bsn.GetRollupConsumerMetadata().FinalityContractAddress, s.contractAddr.String())
}

func (s *FinalityContractTestSuite) Test2CreateBSNFP() {
	// register FP
	fp, err := datagen.GenRandomFinalityProviderWithBTCSK(r, fpSK, "", s.contractCfg.BsnID)
	s.NoError(err)
	msgFP := bstypes.MsgCreateFinalityProvider{
		Addr:        fp.Addr,
		Description: fp.Description,
		BtcPk:       fp.BtcPk,
		Pop:         fp.Pop,
		Commission: bstypes.NewCommissionRates(
			*fp.Commission,
			fp.CommissionInfo.MaxRate,
			fp.CommissionInfo.MaxChangeRate,
		),
		BsnId: s.contractCfg.BsnID,
	}
	err = s.babylonApp.BTCStakingKeeper.AddFinalityProvider(s.ctx, &msgFP)
	s.NoError(err)

	// ensure FP is registered
	fpInDB, err := s.babylonApp.BTCStakingKeeper.GetFinalityProvider(s.ctx, fp.BtcPk.MustMarshal())
	s.NoError(err)
	s.Equal(fp.BtcPk, fpInDB.BtcPk)
}

func (s *FinalityContractTestSuite) Test3CommitAndTimestampPubRand() {
	// increment to epoch 1
	err := s.babylonApp.EpochingKeeper.InitEpoch(s.ctx, []*etypes.Epoch{
		&etypes.Epoch{
			EpochNumber:      1,
			FirstBlockHeight: 1,
		},
	})
	s.NoError(err)
	epoch := s.babylonApp.EpochingKeeper.GetEpoch(s.ctx)
	s.Equal(uint64(1), epoch.EpochNumber)

	// get FP
	fpBTCPK := bbn.NewBIP340PubKeyFromBTCPK(fpPK)
	fp, err := s.babylonApp.BTCStakingKeeper.GetFinalityProvider(s.ctx, fpBTCPK.MustMarshal())
	s.NoError(err)

	// generate secret/public randomness list
	numPubRand := uint64(100)
	commitStartHeight := uint64(1)
	var msg *ftypes.MsgCommitPubRandList
	signingCtx := signingcontext.FpRandCommitContextV0(s.contractCfg.BsnID, s.contractAddr.String())
	randListInfo, msg, err = datagen.GenRandomMsgCommitPubRandList(r, fpSK, signingCtx, commitStartHeight, numPubRand)
	s.NoError(err)

	// construct pub rand commit message
	contractMsg := NewMsgCommitPublicRandomness(
		msg.FpBtcPk.MarshalHex(),
		msg.StartHeight,
		msg.NumPubRand,
		msg.Commitment,
		*msg.Sig,
	)
	contractMsgJson, err := json.Marshal(contractMsg)
	s.NoError(err)

	// commit pub rand
	err = s.ExecuteContract(s.contractAddr, fp.Address(), contractMsgJson)
	s.NoError(err)

	// ensure pub rand commit is in the contract
	query := NewQueryFirstPubRandCommit(fp.BtcPk.MarshalHex())
	queryJson, err := json.Marshal(query)
	s.NoError(err)
	queryResBz := s.QueryContract(s.contractAddr, string(queryJson))
	var queryRes PubRandCommitResponse
	err = json.Unmarshal(queryResBz, &queryRes)
	s.NoError(err)
	s.Equal(msg.StartHeight, queryRes.StartHeight)
	s.Equal(msg.NumPubRand, queryRes.NumPubRand)
	s.Equal(msg.Commitment, queryRes.Commitment)
	s.Equal(uint64(1), queryRes.BabylonEpoch)

	// finalise epoch
	err = s.babylonApp.CheckpointingKeeper.CheckpointsState(s.ctx).CreateRawCkptWithMeta(&ckpttypes.RawCheckpointWithMeta{
		Ckpt: &ckpttypes.RawCheckpoint{
			EpochNum: queryRes.BabylonEpoch,
		},
		Status: ckpttypes.Finalized,
	})
	s.NoError(err)
	s.babylonApp.CheckpointingKeeper.SetLastFinalizedEpoch(s.ctx, queryRes.BabylonEpoch)

	lastFinalizedEpoch := s.babylonApp.CheckpointingKeeper.GetLastFinalizedEpoch(s.ctx)
	s.Equal(queryRes.BabylonEpoch, lastFinalizedEpoch)
}

func (s *FinalityContractTestSuite) Test4SubmitFinalitySignature() {
	// get FP
	fpBTCPK := bbn.NewBIP340PubKeyFromBTCPK(fpPK)
	fp, err := s.babylonApp.BTCStakingKeeper.GetFinalityProvider(s.ctx, fpBTCPK.MustMarshal())
	s.NoError(err)

	// Mock a block with start height 1
	startHeight := uint64(1)
	blockToVote := datagen.GenRandomBlockWithHeight(r, startHeight)
	appHash := blockToVote.AppHash

	idx := 0

	signingCtx := signingcontext.FpFinVoteContextV0(s.contractCfg.BsnID, s.contractAddr.String())
	msgToSign := append([]byte(signingCtx), sdk.Uint64ToBigEndian(startHeight)...)
	msgToSign = append(msgToSign, appHash...)

	// Generate EOTS signature
	sig, err := eots.Sign(fpSK, randListInfo.SRList[idx], msgToSign)
	s.NoError(err)
	eotsSig := bbn.NewSchnorrEOTSSigFromModNScalar(sig)

	contractMsg := NewMsgSubmitFinalitySignature(
		fpBTCPK,
		startHeight,
		&randListInfo.PRList[idx],
		randListInfo.ProofList[idx],
		blockToVote.AppHash,
		eotsSig,
	)
	contractMsgJson, err := json.Marshal(contractMsg)
	s.NoError(err)

	// submit finality signature
	err = s.ExecuteContract(s.contractAddr, fp.Address(), contractMsgJson)
	s.NoError(err)
}

func (s *FinalityContractTestSuite) Test5Slash() {
	// get FP
	fpBTCPK := bbn.NewBIP340PubKeyFromBTCPK(fpPK)
	fp, err := s.babylonApp.BTCStakingKeeper.GetFinalityProvider(s.ctx, fpBTCPK.MustMarshal())
	s.NoError(err)

	// Mock another block with start height 1
	startHeight := uint64(1)
	blockToVote := datagen.GenRandomBlockWithHeight(r, startHeight)
	appHash := blockToVote.AppHash

	idx := 0

	signingCtx := signingcontext.FpFinVoteContextV0(s.contractCfg.BsnID, s.contractAddr.String())
	msgToSign := append([]byte(signingCtx), sdk.Uint64ToBigEndian(startHeight)...)
	msgToSign = append(msgToSign, appHash...)

	// Generate EOTS signature
	sig, err := eots.Sign(fpSK, randListInfo.SRList[idx], msgToSign)
	s.NoError(err)
	eotsSig := bbn.NewSchnorrEOTSSigFromModNScalar(sig)

	contractMsg := NewMsgSubmitFinalitySignature(
		fpBTCPK,
		startHeight,
		&randListInfo.PRList[idx],
		randListInfo.ProofList[idx],
		blockToVote.AppHash,
		eotsSig,
	)
	contractMsgJson, err := json.Marshal(contractMsg)
	s.NoError(err)

	// submit equivocating finality signature
	err = s.ExecuteContract(s.contractAddr, fp.Address(), contractMsgJson)
	s.NoError(err)

	// there should be an evidence on Babylon
	evidence := s.babylonApp.FinalityKeeper.GetFirstSlashableEvidence(s.ctx, fpBTCPK)
	s.NotNil(evidence)
	s.Equal(evidence.FpBtcPk.MustMarshal(), fpBTCPK.MustMarshal())

	// the extracted SK should be the same as the FP's SK
	// Note: it's possible that the extracted SK is the negative of the FP's SK
	extractedSK, err := evidence.ExtractBTCSK()
	s.NoError(err)
	s.True(extractedSK.Key.Equals(&fpSK.Key) || extractedSK.Key.Equals(fpSK.Key.Negate()))
}

func (s *FinalityContractTestSuite) TearDownSuite() {

}

func (s *FinalityContractTestSuite) deployContracts(
	deployer sdk.AccAddress,
	bridgeCodePath string,
) sdk.AccAddress {
	bridgeCodeID, _ := StoreTestCodeCode(s.T(), s.ctx, s.babylonApp, deployer, bridgeCodePath)

	// init message
	bsnID := "test-consumer"
	minPubRand := uint64(100)
	initMsg := NewInitMsg(s.owner.String(), bsnID, minPubRand)
	initMsgBz := []byte(initMsg)
	// instantiate contract
	contractKeeper := keeper.NewDefaultPermissionKeeper(s.babylonApp.WasmKeeper)
	contractAddr, _, err := contractKeeper.Instantiate(s.ctx, bridgeCodeID, deployer, deployer, initMsgBz, "test contract", nil)
	s.NoError(err)

	// query the contract config
	resBz := s.QueryContract(contractAddr, `{"config":{}}`)
	var config Config
	err = json.Unmarshal(resBz, &config)
	s.NoError(err)
	s.Equal(bsnID, config.BsnID)
	s.Equal(minPubRand, config.MinPubRand)

	s.contractCfg = &config

	return contractAddr
}

func (s *FinalityContractTestSuite) NoError(err error, msgAndArgs ...interface{}) {
	require.NoError(s.T(), err, msgAndArgs...)
}

func (s *FinalityContractTestSuite) QueryContract(
	contract sdk.AccAddress,
	request string,
) []byte {
	msgBz := []byte(request)
	resBz, err := s.babylonApp.WasmKeeper.QuerySmart(s.ctx, contract, msgBz)
	s.NoError(err)

	return resBz
}

func (s *FinalityContractTestSuite) ExecuteContract(
	contract sdk.AccAddress,
	caller sdk.AccAddress,
	msg []byte,
) error {
	permKeeper := keeper.NewPermissionedKeeper(
		s.babylonApp.WasmKeeper,
		keeper.DefaultAuthorizationPolicy{},
	)
	_, err := permKeeper.Execute(s.ctx, contract, caller, msg, sdk.Coins{})
	return err
}
