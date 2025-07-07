package e2e

import (
	"encoding/json"
	"math/rand"
	"testing"
	"time"

	"github.com/CosmWasm/wasmd/x/wasm/keeper"
	"github.com/babylonlabs-io/babylon/v3/app"
	"github.com/babylonlabs-io/babylon/v3/testutil/datagen"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	pathToContract = "../artifacts/finality.wasm"
)

var (
	r          = rand.New(rand.NewSource(time.Now().UnixNano()))
	fpSK, _, _ = datagen.GenRandomBTCKeyPair(r)
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
	bsn.ConsumerId = s.contractCfg.ConsumerID
	err := s.babylonApp.BTCStkConsumerKeeper.RegisterConsumer(s.ctx, bsn)
	s.NoError(err)

	// ensure BSN is registered
	bsnInDB, err := s.babylonApp.BTCStkConsumerKeeper.GetConsumerRegister(s.ctx, s.contractCfg.ConsumerID)
	s.NoError(err)
	s.Equal(bsn.ConsumerId, bsnInDB.ConsumerId)
	s.Equal(bsn.ConsumerDescription, bsnInDB.ConsumerDescription)
	s.Equal(bsn.GetRollupConsumerMetadata().FinalityContractAddress, s.contractAddr.String())
}

func (s *FinalityContractTestSuite) Test2CreateBSNFP() {
	// get registered BSN
	bsn, err := s.babylonApp.BTCStkConsumerKeeper.GetConsumerRegister(s.ctx, s.contractCfg.ConsumerID)
	s.NoError(err)

	// register FP
	fp, err := datagen.GenRandomFinalityProviderWithBTCSK(r, fpSK, "", bsn.ConsumerId)
	s.NoError(err)
	s.babylonApp.BTCStkConsumerKeeper.SetConsumerFinalityProvider(s.ctx, fp)

	// ensure FP is registered
	fpInDB, err := s.babylonApp.BTCStkConsumerKeeper.GetConsumerFinalityProvider(s.ctx, bsn.ConsumerId, fp.BtcPk)
	s.NoError(err)
	s.Equal(fp.BtcPk, fpInDB.BtcPk)
}

func (s *FinalityContractTestSuite) TearDownSuite() {

}

func (s *FinalityContractTestSuite) deployContracts(
	deployer sdk.AccAddress,
	bridgeCodePath string,
) sdk.AccAddress {
	bridgeCodeID, _ := StoreTestCodeCode(s.T(), s.ctx, s.babylonApp, deployer, bridgeCodePath)

	// init message
	consumerID := "test-consumer"
	initMsg := NewInitMsg(s.owner.String(), consumerID, true)
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
	s.Equal(consumerID, config.ConsumerID)

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
	minter sdk.AccAddress,
	msg string,
) {
	permKeeper := keeper.NewPermissionedKeeper(
		s.babylonApp.WasmKeeper,
		keeper.DefaultAuthorizationPolicy{},
	)
	msgBz := []byte(msg)
	resp, err := permKeeper.Execute(s.ctx, contract, minter, msgBz, sdk.Coins{})
	s.NoError(err, resp)
}
