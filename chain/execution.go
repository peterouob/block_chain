package chain

import (
	"bytes"
	"crypto/sha3"
	"errors"
)

type TransactionBlock interface {
	Serialize() ([]byte, error)
	Digest() (Digest, error)
}

type ExecutionEngin struct {
	Store ObjectStorer
}

type ExecutionEffect struct {
	Status            TransferStatus
	TransactionDigest Digest
	MutatedObjects    []MutatedObjects
	GasUsed           struct{}
}

func (e ExecutionEffect) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	bw := NewBinWriter(buf)
	statusBytes, err := e.Status.Serialize()
	if err != nil {
		return nil, err
	}

	bw.raw(statusBytes)
	bw.raw(e.TransactionDigest[:])
	bw.write(uint32(len(e.MutatedObjects)))
	for _, m := range e.MutatedObjects {
		mBytes, err := m.Serialize()
		if err != nil {
			return nil, err
		}
		bw.raw(mBytes)
	}

	return buf.Bytes(), nil
}

var ErrDigestFailedFromSerialization = errors.New("digest failed from serialization")

func (e ExecutionEffect) Digest() (Digest, error) {
	buf, err := e.Serialize()
	if err != nil {
		return [32]byte{}, ErrDigestFailedFromSerialization
	}
	return sha3.Sum256(buf), nil
}

type ExecutionDigests struct {
	Transaction Digest
	Effect      Digest
}

func (e ExecutionDigests) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	bw := NewBinWriter(buf)

	bw.raw(e.Transaction[:])
	bw.raw(e.Effect[:])
	return buf.Bytes(), nil
}

type MutatedObjects struct {
	Before ObjectRef
	After  ObjectRef
}

func (m MutatedObjects) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	beforeBytes, err := m.Before.Serialize()
	if err != nil {
		return nil, err
	}

	if _, err := buf.Write(beforeBytes); err != nil {
		return nil, err
	}

	afterBytes, err := m.After.Serialize()
	if err != nil {
		return nil, err
	}

	if _, err := buf.Write(afterBytes); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var (
	ErrExecutionAddrInvalid      = errors.New("execution address invalid")
	ErrExecutionVersionNotEqual  = errors.New("execution version not equal")
	ErrExecutionObjectOwnerType  = errors.New("execution object owner type")
	ErrExecutionSenderNotTheSame = errors.New("execution sender not the same")
	ErrExecutionAssertFailed     = errors.New("execution assert failed")
)

func (e *ExecutionEngin) Execute(tx *TransactionData, signature Signature) (*ExecutionEffect, error) {
	var err error
	effect := &ExecutionEffect{}
	address := signature.DecodeAddress()
	if address != tx.Sender {
		return nil, ErrExecutionAddrInvalid
	}
	intent := IntentTransaction()
	intentMsg := NewIntentMessage(*intent, tx)
	hash, err := intentMsg.Hash()
	if err != nil {
		return nil, err
	}
	if err := signature.Verify(hash); err != nil {
		return nil, err
	}

	if err := tx.Valid(); err != nil {
		return nil, err
	}

	program, ok := tx.Kind.(*ProgrammableTransaction)
	if !ok {
		return nil, ErrExecutionAssertFailed
	}

	objects := make(map[ObjectId]Object)

	for _, input := range program.Inputs {
		switch i := input.(type) {
		case *RefCallArgs:
			obj, err := e.Store.Get(i.Ref.ObjectId)
			if err != nil {
				return nil, err
			}
			if obj.GetVersion() != i.Ref.Version {
				return nil, ErrExecutionVersionNotEqual
			}
			addrOwner, ok := obj.owner.(*AddressOwner)
			if !ok {
				return nil, ErrExecutionObjectOwnerType
			}
			if addrOwner.Address != address {
				return nil, ErrExecutionSenderNotTheSame
			}
			objects[i.Ref.ObjectId] = obj
		default:
			continue
		}
	}

	var oldRef ObjectRef
	var newRef *ObjectRef

	txDigest, err := tx.Hash()
	if err != nil {
		return nil, err
	}

	for _, command := range program.Commands {
		switch c := command.(type) {
		case *TransferObject:
			args, ok := program.Inputs[c.Recipient].(*ValueCallArgs)
			if !ok {
				return nil, ErrExecutionAssertFailed
			}

			for _, objIdx := range c.Objects {
				refCallArg, ok := program.Inputs[objIdx].(*RefCallArgs)
				if !ok {
					return nil, ErrExecutionAssertFailed
				}
				ref := refCallArg.Ref
				oldRef = ref
				obj, ok := objects[ref.ObjectId]
				if !ok {
					return nil, ErrExecutionAssertFailed
				}
				obj.SetOwner(&AddressOwner{args.Address})
				obj.data.IncrementVersion()
				obj.previousTransaction = txDigest
				newRef, err = obj.Ref()
				if err != nil {
					return nil, err
				}
				effect.MutatedObjects = append(effect.MutatedObjects, MutatedObjects{oldRef, *newRef})
				objects[ref.ObjectId] = obj
			}
		}
	}

	for _, obj := range objects {
		if err := e.Store.Put(obj); err != nil {
			return nil, err
		}
	}

	effect.TransactionDigest = txDigest
	effect.Status = TransferStatus{true}
	effect.GasUsed = struct{}{}

	return effect, nil
}

type TransferStatus struct {
	success bool
}

func (t TransferStatus) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	bw := NewBinWriter(buf)
	if t.success {
		bw.raw([]byte{0x01})
		return buf.Bytes(), nil
	}

	bw.raw([]byte{0x00})
	return buf.Bytes(), nil
}
