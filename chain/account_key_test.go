package chain

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/dustinxie/ecc"
	"github.com/stretchr/testify/assert"
)

func TestAccountKeyRoundTrip(t *testing.T) {
	originalPrivKey, err := ecdsa.GenerateKey(ecc.P256k1(), rand.Reader)
	assert.NoError(t, err, "Failed to generate private key")

	customPrivKey := newP256k1PrivateKey(originalPrivKey)

	assert.Equal(t, len(customPrivKey.D), 32)
	assert.Equal(t, len(customPrivKey.RawData), 65)
	assert.Equal(t, customPrivKey.RawData[0], uint8(0x04))
	assert.NotNil(t, customPrivKey.p256k1PublicKey.X())
	assert.NotNil(t, customPrivKey.p256k1PublicKey.Y())

	restorePublicKey := customPrivKey.publicKey()

	assert.Equal(t, restorePublicKey.X.Cmp(originalPrivKey.PublicKey.X), 0)
	assert.Equal(t, restorePublicKey.Y.Cmp(originalPrivKey.PublicKey.Y), 0)

	restorePrivKey := customPrivKey.privateKey()
	assert.Equal(t, restorePrivKey.D.Cmp(originalPrivKey.D), 0)

	msg := []byte("hello blockchain testing")
	hash := sha256.Sum256(msg)

	r, s, err := ecdsa.Sign(rand.Reader, restorePrivKey, hash[:])
	assert.NoError(t, err, "Failed to sign message")
	valid := ecdsa.Verify(restorePublicKey, hash[:], r, s)
	assert.Equal(t, valid, true)

	validOrg := ecdsa.Verify(&originalPrivKey.PublicKey, hash[:], r, s)
	assert.Equal(t, validOrg, true)
}

func TestAccountKeySign(t *testing.T) {
	account, err := NewAccount()
	assert.NoError(t, err)

	intent := IntentTransaction()
	orimsg := IntentType("hello world")
	intentMsg := NewIntentMessage(*intent, orimsg)
	msg, err := intentMsg.Hash()

	assert.NoError(t, err)
	assert.NotEmpty(t, msg)

	sig, err := account.Sign(msg)

	assert.NoError(t, err)
	assert.NotEmpty(t, sig)
	assert.Equal(t, len(sig), 98)

	s := ParseSignature(sig)

	assert.NotNil(t, s.PubKey)
	assert.NotNil(t, s.SigBytes)
	assert.Equal(t, s.Scheme, SchemeType(0x01))

	flag, err := s.Verify(msg)

	assert.NoError(t, err)
	assert.True(t, flag)

	t.Run("wrong schema", func(t *testing.T) {
		sig[0] = 0x02
		s := ParseSignature(sig)
		flag, err := s.Verify(msg)
		assert.ErrorAs(t, err, ErrSchemeNotSupported)
		assert.False(t, flag)
	})

	t.Run("invalid public key", func(t *testing.T) {
		sig = sig[:32]
		s := ParseSignature(sig)
		flag, err := s.Verify(msg)
		assert.ErrorAs(t, err, ErrInvalidPublicKey)
		assert.False(t, flag)
	})

	t.Run("invalid ecdsa verify", func(t *testing.T) {
		msg = []byte("hello world")
		sig, err := account.Sign(msg)
		assert.NoError(t, err)
		assert.NotEmpty(t, sig)
		s := ParseSignature(sig)
		msg = []byte("wrong intent msg")
		flag, err := s.Verify(msg)
		assert.ErrorAs(t, err, ErrEcdsaVerify)
		assert.False(t, flag)
	})

}
