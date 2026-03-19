package chain

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/dustinxie/ecc"
)

type ObjectRef struct {
	ObjectId       Address  `json:"object_id"`
	SequenceNumber uint64   `json:"sequence_number"`
	Digest         [32]byte `json:"digest"`
}

type TransactionType uint8

type TransactionData struct {
	Expiration *TransactionExpiration `json:"expiration,omitempty"`
	Sender     Address                `json:"sender"`
	GasData    GasData                `json:"gas_data"`
	Type       TransactionType        `json:"type"`
}

type GasData struct {
	Owner   Address     `json:"owner"`
	Payment []ObjectRef `json:"payment"`
	Price   uint64      `json:"price"`
	Budget  uint64      `json:"budget"`
}

type EpochId uint64

type TransactionExpiration struct {
	Epoch   *EpochId     `json:"epoch,omitempty"`
	ValidAt *ValidDuring `json:"valid_at,omitempty"`
}

type ValidDuring struct {
	MinEpoch     *EpochId `json:"min_epoch,omitempty"`
	MaxEpoch     *EpochId `json:"max_epoch,omitempty"`
	MinTimeStamp *uint64  `json:"min_time_stamp,omitempty"`
	MaxTimeStamp *uint64  `json:"max_time_stamp,omitempty"`
	Chain        []byte   `json:"chain,omitempty"`
	Nonce        uint32   `json:"nonce,omitempty"`
}

type SchemeType byte

const (
	SchemeSecp256k1 SchemeType = 0x01
)

type Signature struct {
	SigBytes []byte     `json:"sig_bytes"`
	PubKey   []byte     `json:"pub_key"`
	Scheme   SchemeType `json:"scheme"`
}

func ParseSignature(sig []byte) *Signature {
	if len(sig) != 98 {
		panic("invalid signature length")
		return nil
	}

	schema := SchemeType(sig[0])
	sigByte := sig[1:65]
	pubKey := sig[65:]

	return &Signature{
		SigBytes: sigByte,
		PubKey:   pubKey,
		Scheme:   schema,
	}
}

var (
	ErrSchemeNotSupported = errors.New("scheme not supported")
	ErrInvalidPublicKey   = errors.New("invalid public key")
	ErrEcdsaVerify        = errors.New("ecdsa verify failed")
)

func (s *Signature) Verify(intentMsg []byte) (bool, error) {
	if s.Scheme != SchemeSecp256k1 {
		return false, ErrSchemeNotSupported
	}

	rV := new(big.Int).SetBytes(s.SigBytes[:32])
	sV := new(big.Int).SetBytes(s.SigBytes[32:])

	curve := ecc.P256k1()
	x, y, err := DeCompressPubKey(s.PubKey)

	if err != nil {
		return false, err
	}

	if x == nil || y == nil {
		return false, ErrInvalidPublicKey
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	if !ecdsa.Verify(pubKey, intentMsg, rV, sV) {
		return false, ErrEcdsaVerify
	}

	return true, nil
}

type SenderSignedData struct {
	IntentMessage TransactionData `json:"intent_message"`
	TxSignatures  []Signature     `json:"tx_signatures"`
}
