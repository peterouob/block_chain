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

	customPrivKey := newP256PrivateKey(originalPrivKey)

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
