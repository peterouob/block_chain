package chain

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"

	"github.com/dustinxie/ecc"
	"golang.org/x/crypto/sha3"
)

type Address string

func NewAddress(pub *ecdsa.PublicKey) Address {
	jpub, _ := json.Marshal(newP256k1Key(pub))
	hash := make([]byte, 64)
	sha3.ShakeSum256(hash, jpub)
	return Address(hex.EncodeToString(hash[:32]))
}

type Account struct {
	prvKey *ecdsa.PrivateKey
	addr   Address
}

func NewAccount() (*Account, error) {
	prv, err := ecdsa.GenerateKey(ecc.P256k1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	addr := NewAddress(&prv.PublicKey)
	return &Account{prv, addr}, nil
}
