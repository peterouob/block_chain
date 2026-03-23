package chain

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestObjectId(fill byte) ObjectId {
	var id ObjectId
	for i := range id {
		id[i] = fill
	}
	return id
}

func newTestDigest(fill byte) Digest {
	var d Digest
	for i := range d {
		d[i] = fill
	}
	return d
}

func newTestMoveObject() *MoveObject {
	return &MoveObject{
		ObjectId:          newTestObjectId(0xAA),
		Version:           1,
		Type:              "0x2::coin::Coin<SUI>",
		Contents:          []byte{0xDE, 0xAD, 0xBE, 0xEF},
		HasPublicTransfer: true,
	}
}

func newTestMovePackage() *MovePackage {
	return &MovePackage{
		ObjectId: newTestObjectId(0xBB),
		Version:  1,
		Module: map[string][]byte{
			"coin":     {0x01, 0x02, 0x03},
			"transfer": {0x04, 0x05},
			"balance":  {0x06},
		},
	}
}

func newTestObject(data ObjectData, owner Owner) *Object {
	return &Object{
		data:                data,
		owner:               owner,
		previousTransaction: newTestDigest(0xFF),
		storageRebate:       1000,
	}
}

func TestSerialize(t *testing.T) {
	t.Run("TestMoveObjectSerializeDeterministic", func(t *testing.T) {
		obj := newTestMoveObject()
		first, err := obj.Serialize()
		require.NoError(t, err, "序列化不應失敗")

		for i := 0; i < 100; i++ {
			result, err := obj.Serialize()
			require.NoError(t, err)
			assert.Equal(t, first, result, "第 %d 次序列化結果與第一次不同", i)
		}
	})

	t.Run("TestMoveObjectSerializeStructuralEquality", func(t *testing.T) {
		a := newTestMoveObject()
		b := newTestMoveObject()

		bufA, err := a.Serialize()
		require.NoError(t, err)
		bufB, err := b.Serialize()
		require.NoError(t, err)

		assert.Equal(t, bufA, bufB, "欄位相同的兩個實例序列化結果應該相同")
	})

	t.Run("TestMovePackageSerializeDeterministic", func(t *testing.T) {
		pkg := newTestMovePackage()
		first, err := pkg.Serialize()
		require.NoError(t, err)

		for i := 0; i < 100; i++ {
			result, err := pkg.Serialize()
			require.NoError(t, err)
			assert.Equal(t, first, result, "MovePackage 第 %d 次序列化不一致", i)
		}
	})
}

func TestObjectRefDigestDeterministic(t *testing.T) {
	obj := newTestObject(newTestMoveObject(), &AddressOwner{Address: "test_addr"})

	firstRef, err := obj.Ref()
	require.NoError(t, err)

	for i := 0; i < 100; i++ {
		ref, err := obj.Ref()
		require.NoError(t, err)
		assert.Equal(t, firstRef.Digest, ref.Digest, "第 %d 次 Digest 不一致", i)
	}
}

func TestMoveObjectFieldDifference(t *testing.T) {
	base := newTestMoveObject()
	baseBuf, err := base.Serialize()
	require.NoError(t, err)

	tests := []struct {
		name   string
		mutate func() *MoveObject
	}{
		{
			name: "不同 ObjectId",
			mutate: func() *MoveObject {
				m := newTestMoveObject()
				m.ObjectId = newTestObjectId(0x01) // 基準是 0xAA
				return m
			},
		},
		{
			name: "不同 Version",
			mutate: func() *MoveObject {
				m := newTestMoveObject()
				m.Version = 999
				return m
			},
		},
		{
			name: "不同 Type",
			mutate: func() *MoveObject {
				m := newTestMoveObject()
				m.Type = "0x2::nft::NFT"
				return m
			},
		},
		{
			name: "不同 Contents",
			mutate: func() *MoveObject {
				m := newTestMoveObject()
				m.Contents = []byte{0x00}
				return m
			},
		},
		{
			name: "不同 HasPublicTransfer",
			mutate: func() *MoveObject {
				m := newTestMoveObject()
				m.HasPublicTransfer = false // 基準是 true
				return m
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutatedBuf, err := tt.mutate().Serialize()
			require.NoError(t, err)
			assert.NotEqual(t, baseBuf, mutatedBuf,
				"修改 %s 後序列化結果應該不同", tt.name)
		})
	}
}

func TestMovePackageFieldDifference(t *testing.T) {
	base := newTestMovePackage()
	baseBuf, err := base.Serialize()
	require.NoError(t, err)

	tests := []struct {
		name   string
		mutate func() *MovePackage
	}{
		{
			name: "不同 ObjectId",
			mutate: func() *MovePackage {
				p := newTestMovePackage()
				p.ObjectId = newTestObjectId(0x01)
				return p
			},
		},
		{
			name: "不同 Version",
			mutate: func() *MovePackage {
				p := newTestMovePackage()
				p.Version = 999
				return p
			},
		},
		{
			name: "多一個 Module",
			mutate: func() *MovePackage {
				p := newTestMovePackage()
				p.Module["extra"] = []byte{0xFF}
				return p
			},
		},
		{
			name: "Module 內容不同",
			mutate: func() *MovePackage {
				p := newTestMovePackage()
				p.Module["coin"] = []byte{0xFF, 0xFF, 0xFF} // 基準是 {0x01, 0x02, 0x03}
				return p
			},
		},
		{
			name: "少一個 Module",
			mutate: func() *MovePackage {
				p := newTestMovePackage()
				delete(p.Module, "balance")
				return p
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutatedBuf, err := tt.mutate().Serialize()
			require.NoError(t, err)
			assert.NotEqual(t, baseBuf, mutatedBuf,
				"修改 %s 後序列化結果應該不同", tt.name)
		})
	}
}

func TestObjectDigestChangesOnAnyFieldMutation(t *testing.T) {
	base := newTestObject(newTestMoveObject(), &AddressOwner{Address: "owner1"})
	baseRef, err := base.Ref()
	require.NoError(t, err)

	tests := []struct {
		name  string
		build func() *Object
	}{
		{
			name: "不同 Owner",
			build: func() *Object {
				return newTestObject(newTestMoveObject(), &AddressOwner{Address: "owner2"})
			},
		},
		{
			name: "不同 Owner 類型",
			build: func() *Object {
				return newTestObject(newTestMoveObject(), &SharedOwner{SharedVersion: 1})
			},
		},
		{
			name: "不同 previousTransaction",
			build: func() *Object {
				o := newTestObject(newTestMoveObject(), &AddressOwner{Address: "owner1"})
				o.previousTransaction = newTestDigest(0x00) // 基準是 0xFF
				return o
			},
		},
		{
			name: "不同 storageRebate",
			build: func() *Object {
				o := newTestObject(newTestMoveObject(), &AddressOwner{Address: "owner1"})
				o.storageRebate = 9999
				return o
			},
		},
		{
			// 改 data 內容 → Digest 必須變
			name: "不同 data Contents",
			build: func() *Object {
				m := newTestMoveObject()
				m.Contents = []byte{0x00, 0x00}
				return newTestObject(m, &AddressOwner{Address: "owner1"})
			},
		},
		{
			name: "MoveObject vs MovePackage",
			build: func() *Object {
				return newTestObject(newTestMovePackage(), &AddressOwner{Address: "owner1"})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := tt.build().Ref()
			require.NoError(t, err)
			assert.NotEqual(t, baseRef.Digest, ref.Digest,
				"%s: Digest 應該不同", tt.name)
		})
	}
}

func TestMoveObjectNilAndEmptyFields(t *testing.T) {

	tests := []struct {
		name string
		obj  *MoveObject
	}{
		{
			name: "nil Contents",
			obj: &MoveObject{
				ObjectId: newTestObjectId(0x01),
				Version:  1,
				Type:     "test",
				Contents: nil,
			},
		},
		{
			name: "空 Contents",
			obj: &MoveObject{
				ObjectId: newTestObjectId(0x01),
				Version:  1,
				Type:     "test",
				Contents: []byte{},
			},
		},
		{
			name: "空 Type",
			obj: &MoveObject{
				ObjectId: newTestObjectId(0x01),
				Version:  1,
				Type:     "", // 空字串
				Contents: []byte{0x01},
			},
		},
		{
			name: "全零 ObjectId",
			obj: &MoveObject{
				ObjectId: ObjectId{}, // 32 bytes 全零
				Version:  0,
				Type:     "test",
				Contents: []byte{0x01},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf, err := tt.obj.Serialize()
			require.NoError(t, err, "不應返回 error")
			assert.NotEmpty(t, buf, "序列化結果不應為空")
		})
	}
}

func TestMoveObjectNilVsEmptyContentsDifference(t *testing.T) {
	nilObj := &MoveObject{
		ObjectId: newTestObjectId(0x01), Version: 1,
		Type: "test", Contents: nil,
	}
	emptyObj := &MoveObject{
		ObjectId: newTestObjectId(0x01), Version: 1,
		Type: "test", Contents: []byte{},
	}

	nilBuf, err := nilObj.Serialize()
	require.NoError(t, err)
	emptyBuf, err := emptyObj.Serialize()
	require.NoError(t, err)

	assert.Equal(t, nilBuf, emptyBuf,
		"nil 和空 Contents 應該產生相同的序列化結果")
}

func TestMovePackageNilAndEmptyModule(t *testing.T) {
	tests := []struct {
		name string
		pkg  *MovePackage
	}{
		{
			name: "nil Module map",
			pkg: &MovePackage{
				ObjectId: newTestObjectId(0x01),
				Version:  1,
				Module:   nil,
			},
		},
		{
			name: "空 Module map",
			pkg: &MovePackage{
				ObjectId: newTestObjectId(0x01),
				Version:  1,
				Module:   map[string][]byte{},
			},
		},
		{
			name: "Module value 為 nil",
			pkg: &MovePackage{
				ObjectId: newTestObjectId(0x01),
				Version:  1,
				Module:   map[string][]byte{"coin": nil},
			},
		},
		{
			name: "Module key 為空字串",
			pkg: &MovePackage{
				ObjectId: newTestObjectId(0x01),
				Version:  1,
				Module:   map[string][]byte{"": {0x01}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf, err := tt.pkg.Serialize()
			require.NoError(t, err, "不應 panic 或返回 error")
			assert.NotEmpty(t, buf)
		})
	}
}

func TestVersionBoundaryValues(t *testing.T) {
	// uint64 的邊界值測試。
	// 為什麼測 MaxUint64？
	// 如果任何地方把 Version 轉成 int64（有符號），MaxUint64 會變成 -1。
	// 如果轉成 uint32，高位會被截斷。
	// binary.Write 用 LittleEndian 寫 uint64 不會有這個問題，
	// 但防禦性測試確保未來重構不會引入這種 bug。
	versions := []uint64{0, 1, math.MaxUint32, math.MaxUint32 + 1, math.MaxUint64}

	for _, v := range versions {
		t.Run("version_"+string(rune(v)), func(t *testing.T) {
			obj := newTestMoveObject()
			obj.Version = v
			buf, err := obj.Serialize()
			require.NoError(t, err)
			assert.NotEmpty(t, buf)
		})
	}

	results := make(map[uint64][]byte)
	for _, v := range versions {
		obj := newTestMoveObject()
		obj.Version = v
		buf, err := obj.Serialize()
		require.NoError(t, err)
		results[v] = buf
	}

	for i, v1 := range versions {
		for _, v2 := range versions[i+1:] {
			assert.NotEqual(t, results[v1], results[v2],
				"Version %d 和 %d 的序列化結果不應相同", v1, v2)
		}
	}
}

func TestLargeContents(t *testing.T) {
	sizes := []int{
		0,
		1,
		1024,
		1024 * 1024,
		10 * 1024 * 1024,
	}

	for _, size := range sizes {
		obj := newTestMoveObject()
		obj.Contents = make([]byte, size)
		buf, err := obj.Serialize()
		require.NoError(t, err, "Contents 大小 %d 不應失敗", size)
		assert.NotEmpty(t, buf)
	}
}

func TestStorageRebateBoundary(t *testing.T) {
	obj := newTestObject(newTestMoveObject(), &ImmutableOwner{})

	obj.storageRebate = 0
	ref0, err := obj.Ref()
	require.NoError(t, err)

	obj.storageRebate = math.MaxUint64
	refMax, err := obj.Ref()
	require.NoError(t, err)

	assert.NotEqual(t, ref0.Digest, refMax.Digest,
		"不同 storageRebate 應產生不同 Digest")
}

func TestOwnerTypeTag(t *testing.T) {
	tests := []struct {
		name     string
		owner    Owner
		expected byte
	}{
		{"AddressOwner", &AddressOwner{Address: "test"}, AddressOwnerHeader},
		{"ObjectOwner", &ObjectOwner{ParentId: newTestObjectId(0x01)}, ObjectOwnerHeader},
		{"SharedOwner", &SharedOwner{SharedVersion: 42}, SharedOwnerHeader},
		{"ImmutableOwner", &ImmutableOwner{}, ImmutableOwnerHeader},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf, err := tt.owner.serialize()
			require.NoError(t, err)
			require.NotEmpty(t, buf, "序列化結果不應為空")
			assert.Equal(t, tt.expected, buf[0],
				"第一個 byte 應該是 type tag 0x%02X", tt.expected)
		})
	}
}

func TestOwnerTypeTagsAreUnique(t *testing.T) {
	tags := []byte{AddressOwnerHeader, ObjectOwnerHeader, SharedOwnerHeader, ImmutableOwnerHeader}
	seen := make(map[byte]bool)
	for _, tag := range tags {
		assert.False(t, seen[tag], "type tag 0x%02X 重複了", tag)
		seen[tag] = true
	}
}

func TestObjectDataTypeTag(t *testing.T) {
	moveBuf, err := newTestMoveObject().Serialize()
	require.NoError(t, err)

	pkgBuf, err := newTestMovePackage().Serialize()
	require.NoError(t, err)

	assert.Equal(t, byte(MoveObjectHeader), moveBuf[0],
		"MoveObject 第一個 byte 應該是 0x%02X", MoveObjectHeader)
	assert.Equal(t, byte(MoveModuleHeader), pkgBuf[0],
		"MovePackage 第一個 byte 應該是 0x%02X", MoveModuleHeader)
	assert.NotEqual(t, moveBuf[0], pkgBuf[0],
		"MoveObject 和 MovePackage 的 type tag 不應相同")
}

func TestAllTypeTagsGloballyUnique(t *testing.T) {
	allTags := []byte{
		AddressOwnerHeader,
		ObjectOwnerHeader,
		SharedOwnerHeader,
		ImmutableOwnerHeader,
		MoveObjectHeader,
		MoveModuleHeader,
	}
	seen := make(map[byte]string)
	names := []string{
		"AddressOwner", "ObjectOwner", "SharedOwner", "ImmutableOwner",
		"MoveObject", "MovePackage",
	}
	for i, tag := range allTags {
		if existing, exists := seen[tag]; exists {
			t.Errorf("tag 0x%02X 被 %s 和 %s 共用", tag, existing, names[i])
		}
		seen[tag] = names[i]
	}
}

func TestOwnerSerializeDifference(t *testing.T) {
	owner1 := &AddressOwner{Address: "alice"}
	owner2 := &AddressOwner{Address: "bob"}
	buf1, err := owner1.serialize()
	require.NoError(t, err)
	buf2, err := owner2.serialize()
	require.NoError(t, err)
	assert.NotEqual(t, buf1, buf2, "不同地址的 AddressOwner 序列化應不同")

	owners := []Owner{
		&AddressOwner{Address: "test"},
		&ObjectOwner{ParentId: newTestObjectId(0x01)},
		&SharedOwner{SharedVersion: 1},
		&ImmutableOwner{},
	}
	results := make([][]byte, len(owners))
	for i, o := range owners {
		results[i], err = o.serialize()
		require.NoError(t, err)
	}
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			assert.NotEqual(t, results[i], results[j],
				"Owner 類型 %d 和 %d 序列化結果不應相同", i, j)
		}
	}
}

func TestRefConsistencyWithObject(t *testing.T) {
	obj := newTestObject(newTestMoveObject(), &AddressOwner{Address: "test"})
	ref, err := obj.Ref()
	require.NoError(t, err)

	assert.Equal(t, obj.GetObjectID(), ref.ObjectId,
		"Ref 的 ObjectId 應該跟 GetObjectID 一致")
	assert.Equal(t, obj.GetVersion(), ref.Version,
		"Ref 的 Version 應該跟 GetVersion 一致")
}

func TestRefDigestIsNotZero(t *testing.T) {
	obj := newTestObject(newTestMoveObject(), &AddressOwner{Address: "test"})
	ref, err := obj.Ref()
	require.NoError(t, err)

	assert.NotEqual(t, Digest{}, ref.Digest, "Digest 不應為全零")
}

func TestGetObjectIDFromMoveObject(t *testing.T) {
	expectedId := newTestObjectId(0xCC)
	obj := newTestObject(
		&MoveObject{ObjectId: expectedId, Version: 7, Type: "test", Contents: []byte{0x01}},
		&ImmutableOwner{},
	)
	assert.Equal(t, expectedId, obj.GetObjectID())
}

func TestGetObjectIDFromMovePackage(t *testing.T) {
	expectedId := newTestObjectId(0xDD)
	obj := newTestObject(
		&MovePackage{ObjectId: expectedId, Version: 3, Module: map[string][]byte{}},
		&ImmutableOwner{},
	)
	assert.Equal(t, expectedId, obj.GetObjectID())
}

func TestGetVersionFromMoveObject(t *testing.T) {
	obj := newTestObject(
		&MoveObject{ObjectId: newTestObjectId(0x01), Version: 42, Type: "test", Contents: []byte{0x01}},
		&ImmutableOwner{},
	)
	assert.Equal(t, uint64(42), obj.GetVersion())
}

func TestGetVersionFromMovePackage(t *testing.T) {
	obj := newTestObject(
		&MovePackage{ObjectId: newTestObjectId(0x01), Version: 99, Module: map[string][]byte{}},
		&ImmutableOwner{},
	)
	assert.Equal(t, uint64(99), obj.GetVersion())
}

func TestMoveObjectSerializeFormat(t *testing.T) {
	obj := &MoveObject{
		ObjectId:          newTestObjectId(0xAA),
		Version:           1,
		Type:              "AB",
		Contents:          []byte{0xFF},
		HasPublicTransfer: true,
	}

	buf, err := obj.Serialize()
	require.NoError(t, err)

	offset := 0

	assert.Equal(t, byte(MoveObjectHeader), buf[offset], "offset 0: type tag")
	offset += 1

	for i := 0; i < 32; i++ {
		assert.Equal(t, byte(0xAA), buf[offset+i], "offset %d: ObjectId[%d]", offset+i, i)
	}
	offset += 32

	assert.Equal(t, byte(0x01), buf[offset], "offset %d: Version low byte", offset)
	assert.Equal(t, byte(0x00), buf[offset+7], "offset %d: Version high byte", offset+7)
	offset += 8

	assert.Equal(t, byte(0x02), buf[offset], "offset %d: Type length low byte", offset)
	offset += 4

	assert.Equal(t, byte('A'), buf[offset], "offset %d: Type[0]", offset)
	assert.Equal(t, byte('B'), buf[offset+1], "offset %d: Type[1]", offset+1)
	offset += 2

	assert.Equal(t, byte(0x01), buf[offset], "offset %d: Contents length low byte", offset)
	offset += 4

	assert.Equal(t, byte(0xFF), buf[offset], "offset %d: Contents[0]", offset)
	offset += 1

	assert.Equal(t, byte(0x01), buf[offset], "offset %d: HasPublicTransfer", offset)
	offset += 1

	assert.Equal(t, offset, len(buf),
		"序列化總長度應該是 %d，實際是 %d", offset, len(buf))
}
