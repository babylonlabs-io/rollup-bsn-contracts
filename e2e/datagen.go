package e2e

import (
	"math/rand"

	"github.com/babylonlabs-io/babylon/v3/testutil/datagen"
	bbn "github.com/babylonlabs-io/babylon/v3/types"
	ftypes "github.com/babylonlabs-io/babylon/v3/x/finality/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func GenRandomMsgCommitPubRandList(
	r *rand.Rand,
	sk *btcec.PrivateKey,
	signingContext string,
	startHeight uint64,
	numPubRand uint64,
) (*datagen.RandListInfo, *bbn.BIP340Signature, error) {
	randListInfo, err := datagen.GenRandomPubRandList(r, numPubRand)
	if err != nil {
		return nil, nil, err
	}

	msg := &ftypes.MsgCommitPubRandList{
		Signer:      datagen.GenRandomAccount().Address,
		FpBtcPk:     bbn.NewBIP340PubKeyFromBTCPK(sk.PubKey()),
		StartHeight: startHeight,
		NumPubRand:  numPubRand,
		Commitment:  randListInfo.Commitment,
	}
	hash, err := msg.HashToSign(signingContext)
	if err != nil {
		return nil, nil, err
	}
	schnorrSig, err := schnorr.Sign(sk, hash)
	if err != nil {
		return nil, nil, err
	}
	sig := bbn.NewBIP340SignatureFromBTCSig(schnorrSig)
	return randListInfo, sig, nil
}
