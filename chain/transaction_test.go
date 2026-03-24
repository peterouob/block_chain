package chain

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/dustinxie/ecc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAccount(t *testing.T) (*Account, Address) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(ecc.P256k1(), rand.Reader)
	require.NoError(t, err)
	addr := NewAddress(&priv.PublicKey)
	return &Account{prvKey: priv, addr: addr}, addr
}

func putTestObject(t *testing.T, store ObjectStorer, id byte, owner Address, version uint64) Object {
	t.Helper()
	obj := Object{
		data: &MoveObject{
			ObjectId:          newTestObjectId(id),
			Version:           version,
			Type:              "0x2::coin::Coin<SUI>",
			Contents:          []byte{0x01, 0x02},
			HasPublicTransfer: true,
		},
		owner:               &AddressOwner{Address: owner},
		previousTransaction: newTestDigest(0x00),
		storageRebate:       100,
	}
	require.NoError(t, store.Put(obj))
	return obj
}

func buildTransferTx(sender Address, objectRef ObjectRef, recipient Address) *TransactionData {
	inputs := []CallArgs{
		&RefCallArgs{Ref: objectRef},
		&ValueCallArgs{Address: recipient},
	}
	commands := []ProgramCommand{
		&TransferObject{
			Objects:   []uint16{0},
			Recipient: 1,
		},
	}
	program := NewProgrammableTransaction(inputs, commands)
	gasData := GasData{
		Payments: []ObjectRef{},
		Owner:    sender,
		Price:    1000,
		Budget:   10000,
	}
	return NewTransactionData(sender, program, gasData, &NoneExpire{})
}

func signTransaction(t *testing.T, acc *Account, tx *TransactionData) (Signature, []byte) {
	intent := IntentTransaction()
	intentMsg := NewIntentMessage(*intent, tx)
	hash, err := intentMsg.Hash()
	require.NoError(t, err)

	sigBytes, err := acc.Sign(hash)
	require.NoError(t, err)

	sig := ParseSignature(sigBytes)
	require.NotNil(t, sig)
	return *sig, nil
}

func newTestEngine() (*ExecutionEngin, ObjectStorer) {
	store := NewInMemStore()
	engine := &ExecutionEngin{Store: store}
	return engine, store
}

func TestTransferSuccess(t *testing.T) {
	t.Run("TestExecuteTransferSuccess", func(t *testing.T) {
		engine, store := newTestEngine()
		aliceAcc, aliceAddr := newTestAccount(t)
		_, bobAddr := newTestAccount(t)

		obj := putTestObject(t, store, 0x01, aliceAddr, 1)
		objRef, err := obj.Ref()
		require.NoError(t, err)

		tx := buildTransferTx(aliceAddr, *objRef, bobAddr)
		sig, _ := signTransaction(t, aliceAcc, tx)

		effect, err := engine.Execute(tx, sig)
		require.NoError(t, err)
		require.NotNil(t, effect)

		assert.True(t, effect.Status.success)
		assert.Nil(t, effect.Status.err)
		assert.Len(t, effect.MutatedObjects, 1)

		mutated := effect.MutatedObjects[0]
		assert.Equal(t, objRef.ObjectId, mutated.Before.ObjectId)
		assert.Equal(t, objRef.Version, mutated.Before.Version)
		assert.NotEqual(t, mutated.Before.Version, mutated.After.Version)

		updatedObj, err := store.Get(newTestObjectId(0x01))
		require.NoError(t, err)

		addrOwner, ok := updatedObj.owner.(*AddressOwner)
		require.True(t, ok)
		assert.Equal(t, bobAddr, addrOwner.Address)
		assert.Equal(t, uint64(2), updatedObj.GetVersion())

		aliceObjs, err := store.GetByOwner(aliceAddr)
		require.NoError(t, err)
		assert.Empty(t, aliceObjs)

		bobObjs, err := store.GetByOwner(bobAddr)
		require.NoError(t, err)
		assert.Len(t, bobObjs, 1)
	})

	t.Run("TestExecuteTransferMultipleObjects", func(t *testing.T) {

		engine, store := newTestEngine()
		aliceAcc, aliceAddr := newTestAccount(t)
		_, bobAddr := newTestAccount(t)

		obj1 := putTestObject(t, store, 0x01, aliceAddr, 1)
		obj2 := putTestObject(t, store, 0x02, aliceAddr, 1)

		ref1, err := obj1.Ref()
		require.NoError(t, err)
		ref2, err := obj2.Ref()
		require.NoError(t, err)

		inputs := []CallArgs{
			&RefCallArgs{Ref: *ref1},
			&RefCallArgs{Ref: *ref2},
			&ValueCallArgs{Address: bobAddr},
		}
		commands := []ProgramCommand{
			&TransferObject{
				Objects:   []uint16{0, 1},
				Recipient: 2,
			},
		}
		program := NewProgrammableTransaction(inputs, commands)
		gasData := GasData{Owner: aliceAddr, Price: 1000, Budget: 10000}
		tx := NewTransactionData(aliceAddr, program, gasData, &NoneExpire{})

		sig, _ := signTransaction(t, aliceAcc, tx)
		effect, err := engine.Execute(tx, sig)
		require.NoError(t, err)

		assert.Len(t, effect.MutatedObjects, 2)

		bobObjs, err := store.GetByOwner(bobAddr)
		require.NoError(t, err)
		assert.Len(t, bobObjs, 2)

		aliceObjs, err := store.GetByOwner(aliceAddr)
		require.NoError(t, err)
		assert.Empty(t, aliceObjs)
	})
}

func TestTransferFailure(t *testing.T) {
	t.Run("TestExecuteWrongSender", func(t *testing.T) {

		engine, store := newTestEngine()
		_, aliceAddr := newTestAccount(t)
		bobAcc, _ := newTestAccount(t)

		obj := putTestObject(t, store, 0x01, aliceAddr, 1)
		objRef, err := obj.Ref()
		require.NoError(t, err)

		tx := buildTransferTx(aliceAddr, *objRef, aliceAddr)
		sig, _ := signTransaction(t, bobAcc, tx)

		_, err = engine.Execute(tx, sig)
		assert.ErrorIs(t, err, ErrExecutionAddrInvalid)
	})

	t.Run("TestExecuteTamperedTx", func(t *testing.T) {
		engine, store := newTestEngine()
		aliceAcc, aliceAddr := newTestAccount(t)
		_, bobAddr := newTestAccount(t)
		_, charlieAddr := newTestAccount(t)

		obj := putTestObject(t, store, 0x01, aliceAddr, 1)
		objRef, err := obj.Ref()
		require.NoError(t, err)

		txOriginal := buildTransferTx(aliceAddr, *objRef, bobAddr)
		sig, _ := signTransaction(t, aliceAcc, txOriginal)

		txTampered := buildTransferTx(aliceAddr, *objRef, charlieAddr)

		_, err = engine.Execute(txTampered, sig)
		assert.Error(t, err)
	})
}

func TestOwnerFailed(t *testing.T) {
	t.Run("TestExecuteNotOwner", func(t *testing.T) {
		engine, store := newTestEngine()
		aliceAcc, aliceAddr := newTestAccount(t)
		_, bobAddr := newTestAccount(t)

		obj := putTestObject(t, store, 0x01, bobAddr, 1)
		objRef, err := obj.Ref()
		require.NoError(t, err)

		tx := buildTransferTx(aliceAddr, *objRef, aliceAddr)
		sig, _ := signTransaction(t, aliceAcc, tx)

		_, err = engine.Execute(tx, sig)
		assert.ErrorIs(t, err, ErrExecutionSenderNotTheSame)
	})

	t.Run("TestExecuteSharedObjectRejected", func(t *testing.T) {
		engine, store := newTestEngine()
		aliceAcc, aliceAddr := newTestAccount(t)

		sharedObj := Object{
			data: &MoveObject{
				ObjectId: newTestObjectId(0x01),
				Version:  1,
				Type:     "0x2::coin::Coin<SUI>",
				Contents: []byte{0x01},
			},
			owner:               &SharedOwner{SharedVersion: 1},
			previousTransaction: newTestDigest(0x00),
			storageRebate:       0,
		}
		require.NoError(t, store.Put(sharedObj))

		objRef, err := sharedObj.Ref()
		require.NoError(t, err)

		tx := buildTransferTx(aliceAddr, *objRef, aliceAddr)
		sig, _ := signTransaction(t, aliceAcc, tx)

		_, err = engine.Execute(tx, sig)
		assert.ErrorIs(t, err, ErrExecutionObjectOwnerType)
	})

	t.Run("TestExecuteImmutableObjectRejected", func(t *testing.T) {
		engine, store := newTestEngine()
		aliceAcc, aliceAddr := newTestAccount(t)

		immObj := Object{
			data: &MoveObject{
				ObjectId: newTestObjectId(0x01),
				Version:  1,
				Type:     "0x2::package::Package",
				Contents: []byte{0x01},
			},
			owner:               &ImmutableOwner{},
			previousTransaction: newTestDigest(0x00),
			storageRebate:       0,
		}
		require.NoError(t, store.Put(immObj))

		objRef, err := immObj.Ref()
		require.NoError(t, err)

		tx := buildTransferTx(aliceAddr, *objRef, aliceAddr)
		sig, _ := signTransaction(t, aliceAcc, tx)

		_, err = engine.Execute(tx, sig)
		assert.ErrorIs(t, err, ErrExecutionObjectOwnerType)
	})
}

func TestExecuteVersionMismatch(t *testing.T) {
	engine, store := newTestEngine()
	aliceAcc, aliceAddr := newTestAccount(t)
	_, bobAddr := newTestAccount(t)

	obj := putTestObject(t, store, 0x01, aliceAddr, 1)
	objRef, err := obj.Ref()
	require.NoError(t, err)

	tx := buildTransferTx(aliceAddr, *objRef, bobAddr)
	sig, _ := signTransaction(t, aliceAcc, tx)

	obj.data.IncrementVersion()
	require.NoError(t, store.Put(obj))

	_, err = engine.Execute(tx, sig)
	assert.ErrorIs(t, err, ErrExecutionVersionNotEqual)
}

func TestExecuteObjectNotFound(t *testing.T) {
	engine, _ := newTestEngine()
	aliceAcc, aliceAddr := newTestAccount(t)
	_, bobAddr := newTestAccount(t)

	fakeRef := ObjectRef{
		ObjectId: newTestObjectId(0xFF),
		Version:  1,
		Digest:   newTestDigest(0x00),
	}

	tx := buildTransferTx(aliceAddr, fakeRef, bobAddr)
	sig, _ := signTransaction(t, aliceAcc, tx)

	_, err := engine.Execute(tx, sig)
	assert.ErrorIs(t, err, ErrObjectNotFound)
}

func TestExecuteRecipientIndexOutOfBounds(t *testing.T) {
	engine, store := newTestEngine()
	aliceAcc, aliceAddr := newTestAccount(t)

	obj := putTestObject(t, store, 0x01, aliceAddr, 1)
	objRef, err := obj.Ref()
	require.NoError(t, err)

	inputs := []CallArgs{
		&RefCallArgs{Ref: *objRef},
	}
	commands := []ProgramCommand{
		&TransferObject{
			Objects:   []uint16{0},
			Recipient: 5,
		},
	}
	program := NewProgrammableTransaction(inputs, commands)
	gasData := GasData{Owner: aliceAddr, Price: 1000, Budget: 10000}
	tx := NewTransactionData(aliceAddr, program, gasData, &NoneExpire{})

	sig, _ := signTransaction(t, aliceAcc, tx)
	_, err = engine.Execute(tx, sig)
	assert.Error(t, err)
}

func TestExecuteStateConsistency(t *testing.T) {
	t.Run("TestExecuteStoreConsistency", func(t *testing.T) {
		engine, store := newTestEngine()
		aliceAcc, aliceAddr := newTestAccount(t)
		_, bobAddr := newTestAccount(t)

		putTestObject(t, store, 0x01, aliceAddr, 1)
		obj2 := putTestObject(t, store, 0x02, aliceAddr, 1)
		putTestObject(t, store, 0x03, aliceAddr, 1)

		objRef, err := obj2.Ref()
		require.NoError(t, err)

		tx := buildTransferTx(aliceAddr, *objRef, bobAddr)
		sig, _ := signTransaction(t, aliceAcc, tx)

		_, err = engine.Execute(tx, sig)
		require.NoError(t, err)

		aliceObjs, err := store.GetByOwner(aliceAddr)
		require.NoError(t, err)
		assert.Len(t, aliceObjs, 2)

		bobObjs, err := store.GetByOwner(bobAddr)
		require.NoError(t, err)
		assert.Len(t, bobObjs, 1)

		assert.True(t, store.Exists(newTestObjectId(0x01)))
		assert.True(t, store.Exists(newTestObjectId(0x02)))
		assert.True(t, store.Exists(newTestObjectId(0x03)))
	})

	t.Run("TestExecutePreviousTransactionUpdated", func(t *testing.T) {
		engine, store := newTestEngine()
		aliceAcc, aliceAddr := newTestAccount(t)
		_, bobAddr := newTestAccount(t)

		obj := putTestObject(t, store, 0x01, aliceAddr, 1)
		objRef, err := obj.Ref()
		require.NoError(t, err)

		tx := buildTransferTx(aliceAddr, *objRef, bobAddr)
		sig, _ := signTransaction(t, aliceAcc, tx)

		effect, err := engine.Execute(tx, sig)
		require.NoError(t, err)

		updatedObj, err := store.Get(newTestObjectId(0x01))
		require.NoError(t, err)
		assert.Equal(t, effect.TransactionDigest, updatedObj.previousTransaction)
	})

	t.Run("TestExecuteEffectDigestNonZero", func(t *testing.T) {
		engine, store := newTestEngine()
		aliceAcc, aliceAddr := newTestAccount(t)
		_, bobAddr := newTestAccount(t)

		obj := putTestObject(t, store, 0x01, aliceAddr, 1)
		objRef, err := obj.Ref()
		require.NoError(t, err)

		tx := buildTransferTx(aliceAddr, *objRef, bobAddr)
		sig, _ := signTransaction(t, aliceAcc, tx)

		effect, err := engine.Execute(tx, sig)
		require.NoError(t, err)
		assert.NotEqual(t, Digest{}, effect.TransactionDigest)
	})
}

func TestExecuteChainedTransfers(t *testing.T) {
	engine, store := newTestEngine()
	aliceAcc, aliceAddr := newTestAccount(t)
	bobAcc, bobAddr := newTestAccount(t)
	_, charlieAddr := newTestAccount(t)

	obj := putTestObject(t, store, 0x01, aliceAddr, 1)
	objRef, err := obj.Ref()
	require.NoError(t, err)

	tx1 := buildTransferTx(aliceAddr, *objRef, bobAddr)
	sig1, _ := signTransaction(t, aliceAcc, tx1)
	effect1, err := engine.Execute(tx1, sig1)
	require.NoError(t, err)
	assert.Len(t, effect1.MutatedObjects, 1)

	objAfterFirst, err := store.Get(newTestObjectId(0x01))
	require.NoError(t, err)
	assert.Equal(t, uint64(2), objAfterFirst.GetVersion())

	newObjRef, err := objAfterFirst.Ref()
	require.NoError(t, err)

	tx2 := buildTransferTx(bobAddr, *newObjRef, charlieAddr)
	sig2, _ := signTransaction(t, bobAcc, tx2)
	effect2, err := engine.Execute(tx2, sig2)
	require.NoError(t, err)
	assert.Len(t, effect2.MutatedObjects, 1)

	finalObj, err := store.Get(newTestObjectId(0x01))
	require.NoError(t, err)
	assert.Equal(t, uint64(3), finalObj.GetVersion())

	charlieOwner, ok := finalObj.owner.(*AddressOwner)
	require.True(t, ok)
	assert.Equal(t, charlieAddr, charlieOwner.Address)

	aliceObjs, _ := store.GetByOwner(aliceAddr)
	assert.Empty(t, aliceObjs)
	bobObjs, _ := store.GetByOwner(bobAddr)
	assert.Empty(t, bobObjs)
	charlieObjs, _ := store.GetByOwner(charlieAddr)
	assert.Len(t, charlieObjs, 1)
}
