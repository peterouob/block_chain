package chain

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/dustinxie/ecc"
)

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

func (s *Signature) Verify(intentMsg []byte) error {
	if s.Scheme != SchemeSecp256k1 {
		return ErrSchemeNotSupported
	}

	rV := new(big.Int).SetBytes(s.SigBytes[:32])
	sV := new(big.Int).SetBytes(s.SigBytes[32:])

	curve := ecc.P256k1()
	x, y, err := DeCompressPubKey(s.PubKey)

	if err != nil {
		return err
	}

	if x == nil || y == nil {
		return ErrInvalidPublicKey
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	if !ecdsa.Verify(pubKey, intentMsg, rV, sV) {
		return ErrEcdsaVerify
	}

	return nil
}

func (s *Signature) DecodeAddress() Address {
	pubKey := ByteToPubKey(s.PubKey)
	return NewAddress(pubKey)
}
