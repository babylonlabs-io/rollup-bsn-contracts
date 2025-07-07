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
	r = rand.New(rand.NewSource(time.Now().UnixNano()))
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
	consumer := datagen.GenRandomRollupRegister(r, s.contractAddr.String())
	consumer.ConsumerId = s.contractCfg.ConsumerID
	err := s.babylonApp.BTCStkConsumerKeeper.RegisterConsumer(s.ctx, consumer)
	s.NoError(err)

	consumerInDB, err := s.babylonApp.BTCStkConsumerKeeper.GetConsumerRegister(s.ctx, s.contractCfg.ConsumerID)
	s.NoError(err)
	s.Equal(consumer.ConsumerId, consumerInDB.ConsumerId)
	s.Equal(consumer.ConsumerDescription, consumerInDB.ConsumerDescription)
	s.Equal(consumer.GetRollupConsumerMetadata().FinalityContractAddress, s.contractAddr.String())
}

func (s *FinalityContractTestSuite) Test1RegisterCreateBSNFP() {
	_, err := s.babylonApp.BTCStkConsumerKeeper.GetConsumerRegister(s.ctx, s.contractCfg.ConsumerID)
	s.NoError(err)

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
