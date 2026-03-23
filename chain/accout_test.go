package chain

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCMKey(t *testing.T) {
	account, err := NewAccount()
	assert.NoError(t, err)

	var msg = []byte("hello blockchain")
	var pass = []byte("password")

	enc, err := account.encPassword(msg, pass)
	assert.NoError(t, err)
	assert.NotEqual(t, msg, enc)
	assert.NotNil(t, enc)

	dec, err := account.decPassword(enc, pass)
	assert.NoError(t, err)
	assert.NotEqual(t, enc, dec)
	assert.Equal(t, msg, dec)
}

func TestAccountWriteRead(t *testing.T) {
	account, err := NewAccount()
	assert.NoError(t, err)
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "test")
	pass := []byte("password")

	err = account.Write(dir, pass)
	assert.NoError(t, err)

	expectFilePath := filepath.Join(dir, string(account.addr))
	info, err := os.Stat(expectFilePath)
	assert.NoError(t, err)
	assert.True(t, info.Mode().IsRegular())

	a, err := account.Read(expectFilePath, pass)
	assert.NoError(t, err)
	assert.NotNil(t, a)

	pass = []byte("wrong password")
	a, err = account.Read(expectFilePath, pass)
	assert.Error(t, err)
	assert.Nil(t, a)

	account2, _ := NewAccount()
	_, err = account2.Read(expectFilePath, pass)
	require.Error(t, err)
	pass = []byte("wrong password 123123")
	err = account2.Write(dir, pass)
	require.NoError(t, err)
}
