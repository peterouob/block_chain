package chain

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/dustinxie/ecc"
	"golang.org/x/crypto/argon2"
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

func (a *Account) Write(dir string, pass []byte) error {
	jprv, err := a.encodePriveKey()
	if err != nil {
		return err
	}
	cprv, err := a.encPassword(jprv, pass)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	path := filepath.Join(dir, string(a.addr))
	return os.WriteFile(path, cprv, 0600)
}

func (a *Account) Read(path string, pass []byte) (*Account, error) {
	cprv, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	jprv, err := a.decPassword(cprv, pass)
	if err != nil {
		return nil, err
	}

	return a.decodePriveKey(jprv)
}

func (a *Account) encodePriveKey() ([]byte, error) {
	return json.Marshal(newP256PrivateKey(a.prvKey))
}

func (a *Account) decodePriveKey(jprv []byte) (*Account, error) {
	var pk p256PrivateKey

	if err := json.Unmarshal(jprv, &pk); err != nil {
		return nil, err
	}

	prv := pk.privateKey()
	addr := NewAddress(&prv.PublicKey)
	return &Account{prv, addr}, nil
}

const encLen = 32

func (a *Account) encPassword(msg, pass []byte) ([]byte, error) {
	salt := make([]byte, encLen)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key := argon2.IDKey(pass, salt, 1, 256, 1, encLen)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	ciph := gcm.Seal(nonce, nonce, msg, nil)
	ciph = append(salt, ciph...)
	return ciph, nil
}

func (a *Account) decPassword(ciph, pass []byte) ([]byte, error) {
	ciph, salt := ciph[encLen:], ciph[:encLen]
	key := argon2.IDKey(pass, salt, 1, 256, 1, encLen)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	gcmLen := gcm.NonceSize()
	ciph, nonce := ciph[gcmLen:], ciph[:gcmLen]
	msg, err := gcm.Open(nil, nonce, ciph, nil)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (a *Account) Addr() Address {
	return a.addr
}
