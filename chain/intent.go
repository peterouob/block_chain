package chain

import (
	"github.com/fardream/go-bcs/bcs"
	"golang.org/x/crypto/blake2b"
)

type IntentScope uint8

const (
	TransactionDataScope       IntentScope = 0
	IntentScopePersonalMessage IntentScope = 3
)

// Intent
// Scope use in the intent range and lifecycle
// Version use in the blockchain to approve to distinguish the operation version
// AppId use in the frontend/app which intent to chain
type Intent struct {
	Scope   IntentScope
	Version uint8
	AppId   uint8
}

func (i *Intent) ToBytes() [3]byte {
	return [3]byte{byte(i.Scope), i.Version, i.AppId}
}

func IntentTransaction() *Intent {
	return &Intent{
		Scope:   TransactionDataScope,
		Version: 0,
		AppId:   0,
	}
}

type BCSMarshall interface {
	BCSByte() ([]byte, error)
}

type IntentMessage[T BCSMarshall] struct {
	Value  T
	Intent Intent
}

func NewIntentMessage[T BCSMarshall](intent Intent, value T) *IntentMessage[T] {
	return &IntentMessage[T]{
		Intent: intent,
		Value:  value,
	}
}

type IntentType []byte

func (in IntentType) BCSByte() ([]byte, error) {
	return in, nil
}

func (i *IntentMessage[T]) Hash() ([]byte, error) {
	valueByte, err := i.Value.BCSByte()
	if err != nil {
		return nil, err
	}

	intentMsg := i.Intent.ToBytes()

	h, _ := blake2b.New256(nil)
	h.Write(intentMsg[:])
	h.Write(valueByte)
	return h.Sum(nil), nil
}

func (i *IntentMessage[T]) BCSByte() ([]byte, error) {
	bytes, err := bcs.Marshal(i)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
