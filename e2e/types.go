package e2e

import (
	"fmt"

	bbn "github.com/babylonlabs-io/babylon/v3/types"
	"github.com/cometbft/cometbft/crypto/merkle"
)

func NewInitMsg(admin string, bsnID string, minPubRand uint64) string {
	initMsg := fmt.Sprintf(`{"admin":"%s","bsn_id":"%s","min_pub_rand":%d}`, admin, bsnID, minPubRand)
	return initMsg
}

type Config struct {
	BsnID      string `json:"bsn_id"`
	MinPubRand uint64 `json:"min_pub_rand"`
}

type CommitPublicRandomnessMsg struct {
	CommitPublicRandomness CommitPublicRandomnessMsgParams `json:"commit_public_randomness"`
}

type CommitPublicRandomnessMsgParams struct {
	FpPubkeyHex string `json:"fp_pubkey_hex"`
	StartHeight uint64 `json:"start_height"`
	NumPubRand  uint64 `json:"num_pub_rand"`
	Commitment  []byte `json:"commitment"`
	Signature   []byte `json:"signature"`
}

func NewMsgCommitPublicRandomness(fpPubkeyHex string, startHeight uint64, numPubRand uint64, commitment []byte, signature []byte) CommitPublicRandomnessMsg {
	return CommitPublicRandomnessMsg{
		CommitPublicRandomness: CommitPublicRandomnessMsgParams{
			FpPubkeyHex: fpPubkeyHex,
			StartHeight: startHeight,
			NumPubRand:  numPubRand,
			Commitment:  commitment,
			Signature:   signature,
		},
	}
}

// TODO: need to update based on contract implementation
type CommitPublicRandomnessResponse struct {
	Result bool `json:"result"`
}

type SubmitFinalitySignatureMsg struct {
	SubmitFinalitySignature SubmitFinalitySignatureMsgParams `json:"submit_finality_signature"`
}

type SubmitFinalitySignatureMsgParams struct {
	FpPubkeyHex string `json:"fp_pubkey_hex"`
	Height      uint64 `json:"height"`
	PubRand     []byte `json:"pub_rand"`
	Proof       Proof  `json:"proof"`
	BlockHash   []byte `json:"block_hash"`
	Signature   []byte `json:"signature"`
}

func NewMsgSubmitFinalitySignature(
	fpPK *bbn.BIP340PubKey,
	height uint64,
	pubRand *bbn.SchnorrPubRand,
	proof *merkle.Proof,
	blockHash []byte,
	signature *bbn.SchnorrEOTSSig,
) SubmitFinalitySignatureMsg {
	return SubmitFinalitySignatureMsg{
		SubmitFinalitySignature: SubmitFinalitySignatureMsgParams{
			FpPubkeyHex: fpPK.MarshalHex(),
			Height:      height,
			PubRand:     pubRand.MustMarshal(),
			Proof: Proof{
				Total:    uint64(proof.Total),
				Index:    uint64(proof.Index),
				LeafHash: proof.LeafHash,
				Aunts:    proof.Aunts,
			},
			BlockHash: blockHash,
			Signature: signature.MustMarshal(),
		},
	}
}

type AddToAllowlistMsg struct {
	AddToAllowlist AddToAllowlistMsgParams `json:"add_to_allowlist"`
}

type AddToAllowlistMsgParams struct {
	FpPubkeyHexList []string `json:"fp_pubkey_hex_list"`
}

func NewMsgAddToAllowlist(fpPubkeyHexList []string) AddToAllowlistMsg {
	return AddToAllowlistMsg{
		AddToAllowlist: AddToAllowlistMsgParams{
			FpPubkeyHexList: fpPubkeyHexList,
		},
	}
}

type RemoveFromAllowlistMsg struct {
	RemoveFromAllowlist RemoveFromAllowlistMsgParams `json:"remove_from_allowlist"`
}

type RemoveFromAllowlistMsgParams struct {
	FpPubkeyHexList []string `json:"fp_pubkey_hex_list"`
}

func NewMsgRemoveFromAllowlist(fpPubkeyHexList []string) RemoveFromAllowlistMsg {
	return RemoveFromAllowlistMsg{
		RemoveFromAllowlist: RemoveFromAllowlistMsgParams{
			FpPubkeyHexList: fpPubkeyHexList,
		},
	}
}

// TODO: need to update based on contract implementation
type SubmitFinalitySignatureResponse struct {
	Result bool `json:"result"`
}

type QueryMsg struct {
	Config                   *Config        `json:"config,omitempty"`
	FirstPubRandCommit       *PubRandCommit `json:"first_pub_rand_commit,omitempty"`
	LastPubRandCommit        *PubRandCommit `json:"last_pub_rand_commit,omitempty"`
	AllowedFinalityProviders *struct{}      `json:"allowed_finality_providers,omitempty"`
	// BlockVoters is used to query the voters for a specific block
	BlockVoters *BlockVoters `json:"block_voters,omitempty"`
}

type PubRandCommit struct {
	BtcPkHex string `json:"btc_pk_hex"`
}

type PubRandCommitResponse struct {
	StartHeight  uint64 `json:"start_height"`
	NumPubRand   uint64 `json:"num_pub_rand"`
	BabylonEpoch uint64 `json:"babylon_epoch"`
	Commitment   []byte `json:"commitment"`
}

func NewQueryFirstPubRandCommit(btcPkHex string) QueryMsg {
	return QueryMsg{
		FirstPubRandCommit: &PubRandCommit{
			BtcPkHex: btcPkHex,
		},
	}
}

func NewQueryAllowedFinalityProviders() QueryMsg {
	return QueryMsg{
		AllowedFinalityProviders: &struct{}{},
	}
}

// FIXME: Remove this ancillary struct.
// Only required because the e2e tests are using a zero index, which is removed by the `json:"omitempty"` annotation in
// the original cmtcrypto Proof
type Proof struct {
	Total    uint64   `json:"total"`
	Index    uint64   `json:"index"`
	LeafHash []byte   `json:"leaf_hash"`
	Aunts    [][]byte `json:"aunts"`
}

type BlockVoters struct {
	Height uint64 `json:"height"`
	// The block app hash is expected to be in hex format, without the 0x prefix
	HashHex string `json:"hash_hex"`
}

// List of finality provider information who voted for the block
type BlockVotersResponse []BlockVoterInfo

type BlockVoterInfo struct {
	FpBtcPkHex        string          `json:"fp_btc_pk_hex"`
	PubRand           []byte          `json:"pub_rand"`
	FinalitySignature FinalitySigInfo `json:"finality_signature"`
}

type FinalitySigInfo struct {
	// the finality signature
	FinalitySig []byte `json:"finality_sig"`
	// the block hash that the finality signature is for
	BlockHash []byte `json:"block_hash"`
}
