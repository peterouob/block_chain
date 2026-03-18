package chain

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntentMessage_Hash(t *testing.T) {
	intent := IntentTransaction()
	msg := IntentType("hello world")
	intentMsg := NewIntentMessage(*intent, msg)
	hash, err := intentMsg.Hash()
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, hash, msg)
}

func BenchmarkIntentMessage_Hash(b *testing.B) {
	data := make(IntentType, 1024*1024)
	rand.Read(data)
	intent := IntentTransaction()
	intentMsg := NewIntentMessage(*intent, data)
	b.ResetTimer()

	b.Run("HASH", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			hash, err := intentMsg.Hash()
			assert.NoError(b, err)
			assert.NotEmpty(b, hash)
		}
	})
}
