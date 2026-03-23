package object

import (
	"fmt"
	"sync"
	"testing"

	"github.com/peterouob/block_chain/chain/account"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newStoreTestObject(id byte, owner Owner) Object {
	return Object{
		data: &MoveObject{
			ObjectId:          newTestObjectId(id),
			Version:           1,
			Type:              "0x2::coin::Coin<SUI>",
			Contents:          []byte{0x01, 0x02},
			HasPublicTransfer: true,
		},
		owner:               owner,
		previousTransaction: newTestDigest(0xCC),
		storageRebate:       100,
	}
}

func TestStoreCRUD(t *testing.T) {
	t.Run("PutAndGet", func(t *testing.T) {
		store := NewInMemStore()
		obj := newStoreTestObject(0x01, &AddressOwner{Address: "alice"})

		require.NoError(t, store.Put(obj))

		got, err := store.Get(newTestObjectId(0x01))
		require.NoError(t, err)
		assert.Equal(t, obj.GetObjectID(), got.GetObjectID())
		assert.Equal(t, obj.GetVersion(), got.GetVersion())
	})

	t.Run("GetNotFound", func(t *testing.T) {
		store := NewInMemStore()
		_, err := store.Get(newTestObjectId(0xFF))
		assert.ErrorIs(t, err, ErrObjectNotFound)
	})

	t.Run("Delete", func(t *testing.T) {
		store := NewInMemStore()
		obj := newStoreTestObject(0x01, &AddressOwner{Address: "alice"})

		require.NoError(t, store.Put(obj))
		require.NoError(t, store.Delete(newTestObjectId(0x01)))

		_, err := store.Get(newTestObjectId(0x01))
		assert.ErrorIs(t, err, ErrObjectNotFound)
	})

	t.Run("DeleteNonExistent", func(t *testing.T) {
		store := NewInMemStore()
		err := store.Delete(newTestObjectId(0xFF))
		assert.NoError(t, err)
	})

	t.Run("Exists", func(t *testing.T) {
		store := NewInMemStore()
		id := newTestObjectId(0x01)
		obj := newStoreTestObject(0x01, &AddressOwner{Address: "alice"})

		assert.False(t, store.Exists(id))
		require.NoError(t, store.Put(obj))
		assert.True(t, store.Exists(id))

		require.NoError(t, store.Delete(id))
		assert.False(t, store.Exists(id))
	})

	t.Run("PutOverwrite", func(t *testing.T) {
		store := NewInMemStore()
		obj1 := newStoreTestObject(0x01, &AddressOwner{Address: "alice"})
		obj1.storageRebate = 100
		require.NoError(t, store.Put(obj1))

		obj2 := newStoreTestObject(0x01, &AddressOwner{Address: "alice"})
		obj2.storageRebate = 999
		require.NoError(t, store.Put(obj2))

		got, err := store.Get(newTestObjectId(0x01))
		require.NoError(t, err)
		assert.Equal(t, uint64(999), got.storageRebate)
	})

	t.Run("MovePackage", func(t *testing.T) {
		store := NewInMemStore()
		pkg := &MovePackage{
			ObjectId: newTestObjectId(0xDD),
			Version:  1,
			Module:   map[string][]byte{"coin": {0x01}},
		}
		obj := Object{
			data:                pkg,
			owner:               &ImmutableOwner{},
			previousTransaction: newTestDigest(0xAA),
			storageRebate:       0,
		}
		require.NoError(t, store.Put(obj))
		got, err := store.Get(newTestObjectId(0xDD))
		require.NoError(t, err)
		assert.Equal(t, newTestObjectId(0xDD), got.GetObjectID())
	})
}

func TestStoreOwnerQueries(t *testing.T) {
	t.Run("GetByOwnerBasic", func(t *testing.T) {
		store := NewInMemStore()
		require.NoError(t, store.Put(newStoreTestObject(0x01, &AddressOwner{Address: "alice"})))
		require.NoError(t, store.Put(newStoreTestObject(0x02, &AddressOwner{Address: "alice"})))
		require.NoError(t, store.Put(newStoreTestObject(0x03, &AddressOwner{Address: "bob"})))

		aliceObjs, _ := store.GetByOwner("alice")
		assert.Len(t, aliceObjs, 2)
		bobObjs, _ := store.GetByOwner("bob")
		assert.Len(t, bobObjs, 1)
	})

	t.Run("GetByOwnerEmpty", func(t *testing.T) {
		store := NewInMemStore()
		objs, err := store.GetByOwner("nobody")
		require.NoError(t, err)
		assert.Empty(t, objs)
	})

	t.Run("GetByOwnerAfterDelete", func(t *testing.T) {
		store := NewInMemStore()
		obj := newStoreTestObject(0x01, &AddressOwner{Address: "alice"})
		require.NoError(t, store.Put(obj))
		require.NoError(t, store.Delete(newTestObjectId(0x01)))

		objs, _ := store.GetByOwner("alice")
		assert.Empty(t, objs)
	})

	t.Run("DeleteAllFromOwner", func(t *testing.T) {
		store := NewInMemStore()
		for i := byte(0); i < 5; i++ {
			require.NoError(t, store.Put(newStoreTestObject(i, &AddressOwner{Address: "alice"})))
		}
		for i := byte(0); i < 5; i++ {
			require.NoError(t, store.Delete(newTestObjectId(i)))
		}
		objs, _ := store.GetByOwner("alice")
		assert.Empty(t, objs)
	})

	t.Run("ManyObjects", func(t *testing.T) {
		store := NewInMemStore()
		count := 1000
		for i := 0; i < count; i++ {
			addr := account.Address(fmt.Sprintf("addr_%d", i%10))
			obj := newStoreTestObject(byte(i%256), &AddressOwner{Address: addr})
			obj.data.(*MoveObject).ObjectId = ObjectId{byte(i >> 8), byte(i)}
			require.NoError(t, store.Put(obj))
		}
		for i := 0; i < 10; i++ {
			addr := account.Address(fmt.Sprintf("addr_%d", i))
			objs, _ := store.GetByOwner(addr)
			assert.Equal(t, 100, len(objs))
		}
	})
}

func TestStoreOwnershipTransfers(t *testing.T) {
	t.Run("AddressToAddress", func(t *testing.T) {
		store := NewInMemStore()
		obj := newStoreTestObject(0x01, &AddressOwner{Address: "alice"})
		require.NoError(t, store.Put(obj))

		obj.owner = &AddressOwner{Address: "bob"}
		require.NoError(t, store.Put(obj))

		aliceObjs, _ := store.GetByOwner("alice")
		assert.Empty(t, aliceObjs)
		bobObjs, _ := store.GetByOwner("bob")
		assert.Len(t, bobObjs, 1)
	})

	t.Run("AddressToSharedOrImmutable", func(t *testing.T) {
		store := NewInMemStore()
		obj := newStoreTestObject(0x01, &AddressOwner{Address: "alice"})
		require.NoError(t, store.Put(obj))
		obj.owner = &SharedOwner{SharedVersion: 5}
		require.NoError(t, store.Put(obj))

		aliceObjs, _ := store.GetByOwner("alice")
		assert.Empty(t, aliceObjs)
		assert.True(t, store.Exists(newTestObjectId(0x01)))

		obj2 := newStoreTestObject(0x02, &AddressOwner{Address: "alice"})
		require.NoError(t, store.Put(obj2))
		obj2.owner = &ImmutableOwner{}
		require.NoError(t, store.Put(obj2))

		aliceObjs, _ = store.GetByOwner("alice")
		assert.Empty(t, aliceObjs)
	})

	t.Run("SpecialOwners", func(t *testing.T) {
		store := NewInMemStore()
		require.NoError(t, store.Put(newStoreTestObject(0x01, &SharedOwner{SharedVersion: 1})))
		require.NoError(t, store.Put(newStoreTestObject(0x02, &ImmutableOwner{})))
		require.NoError(t, store.Put(newStoreTestObject(0x03, &ObjectOwner{ParentId: newTestObjectId(0xEE)})))

		assert.True(t, store.Exists(newTestObjectId(0x01)))
		assert.True(t, store.Exists(newTestObjectId(0x02)))
		assert.True(t, store.Exists(newTestObjectId(0x03)))
	})
}

func TestStoreConcurrency(t *testing.T) {
	t.Run("ConcurrentPutAndGet", func(t *testing.T) {
		store := NewInMemStore()
		var wg sync.WaitGroup
		n := 100
		for i := 0; i < n; i++ {
			wg.Go(func() {
				obj := newStoreTestObject(byte(i), &AddressOwner{Address: "alice"})
				obj.data.(*MoveObject).ObjectId = ObjectId{byte(i)}
				_ = store.Put(obj)
			})
			wg.Go(func() {
				_, _ = store.Get(ObjectId{byte(i)})
			})
		}
		wg.Wait()
	})

	t.Run("ConcurrentOwnerTransfer", func(t *testing.T) {
		store := NewInMemStore()
		n := 50
		for i := 0; i < n; i++ {
			require.NoError(t, store.Put(newStoreTestObject(byte(i), &AddressOwner{Address: "alice"})))
		}
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Go(func() {
				obj := newStoreTestObject(byte(i), &AddressOwner{Address: "bob"})
				_ = store.Put(obj)
			})
		}
		wg.Wait()
		aliceObjs, _ := store.GetByOwner("alice")
		bobObjs, _ := store.GetByOwner("bob")
		assert.Equal(t, n, len(aliceObjs)+len(bobObjs))
	})
}
