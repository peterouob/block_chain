package chain

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/dustinxie/ecc"
)

func TestAccountKeyRoundTrip(t *testing.T) {
	originalPrivKey, err := ecdsa.GenerateKey(ecc.P256k1(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	customPrivKey := newP256PrivateKey(originalPrivKey)

	if len(customPrivKey.D) != 32 {
		t.Errorf("Expected private key data to be 32 bytes, got %d", len(customPrivKey.D))
	}

	if len(customPrivKey.RawData) != 65 || customPrivKey.RawData[0] != 0x04 {
		t.Errorf("Expected uncompressed public key to be 65 bytes starting with 0x04")
	}

	if customPrivKey.p256k1PublicKey.X() == nil {
		t.Errorf("Expected public key to have X coordinate")
	}

	if customPrivKey.p256k1PublicKey.Y() == nil {
		t.Errorf("Expected public key to have Y coordinate")
	}

	restorePublicKey := customPrivKey.publicKey()

	if restorePublicKey.X.Cmp(originalPrivKey.PublicKey.X) != 0 {
		t.Errorf("Expected public key X coordinate to match original")
	}

	if restorePublicKey.Y.Cmp(originalPrivKey.PublicKey.Y) != 0 {
		t.Errorf("Expected public key Y coordinate to match original")
	}

	restorePrivKey := customPrivKey.privateKey()
	if restorePrivKey.D.Cmp(originalPrivKey.D) != 0 {
		t.Errorf("Expected private key to match original")
	}

	msg := []byte("hello blockchain testing")
	hash := sha256.Sum256(msg)

	r, s, err := ecdsa.Sign(rand.Reader, restorePrivKey, hash[:])
	if err != nil {
		t.Errorf("Failed to sign message: %v", err)
	}

	valid := ecdsa.Verify(restorePublicKey, hash[:], r, s)
	if !valid {
		t.Errorf("Failed to verify signature of message: %v", err)
	}

	validOrg := ecdsa.Verify(&originalPrivKey.PublicKey, hash[:], r, s)
	if !validOrg {
		t.Errorf("Failed to verify signature of message: %v", err)
	}
}
