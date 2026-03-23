package chain

import (
	"bytes"
	"encoding/binary"
	"maps"
	"slices"

	"golang.org/x/crypto/sha3"
)

type binWriter struct {
	w   *bytes.Buffer
	err error
}

func (bw *binWriter) write(data any) {
	if bw.err != nil {
		return
	}
	bw.err = binary.Write(bw.w, binary.LittleEndian, data)
}

func (bw *binWriter) raw(p []byte) {
	if bw.err != nil {
		return
	}
	_, bw.err = bw.w.Write(p)
}

type (
	ObjectId [32]byte
	Digest   [32]byte
)

type Object struct {
	data                ObjectData
	owner               Owner
	previousTransaction Digest
	storageRebate       uint64
}

func (o *Object) Serialize() ([]byte, error) {
	// TODO: forbedan big data
	buf := bytes.NewBuffer(nil)
	bf := &binWriter{w: buf}
	data, err := o.data.Serialize()
	if err != nil {
		return nil, err
	}
	bf.raw(data)
	owner, err := o.owner.serialize()
	if err != nil {
		return nil, err
	}
	bf.raw(owner)
	bf.raw(o.previousTransaction[:])
	bf.write(o.storageRebate)
	return buf.Bytes(), bf.err
}

func (o *Object) GetObjectID() ObjectId {
	info := o.data.getInformation()
	return info.objectId
}

func (o *Object) GetVersion() uint64 {
	info := o.data.getInformation()
	return info.version
}

type ObjectRef struct {
	ObjectId ObjectId
	Version  uint64
	Digest   Digest
}

func (o *Object) Ref() (*ObjectRef, error) {
	buf, err := o.Serialize()
	if err != nil {
		return nil, err
	}
	digest := sha3.Sum256(buf)
	return &ObjectRef{o.GetObjectID(), o.GetVersion(), digest}, nil
}

const (
	AddressOwnerHeader   = 0x01
	ObjectOwnerHeader    = 0x02
	SharedOwnerHeader    = 0x03
	ImmutableOwnerHeader = 0x04
)

// Owner have 4 type
// 1. AddressOwner
// 2. ObjectOwner
// 3. SharedOwner
// 4. ImmutableOwner
type Owner interface {
	ownerKind()
	serialize() ([]byte, error)
}

type AddressOwner struct {
	Address Address
}

func (a *AddressOwner) ownerKind() {}
func (a *AddressOwner) serialize() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	bw := &binWriter{w: buf}
	bw.raw([]byte{AddressOwnerHeader})
	bw.write(uint32(len(a.Address)))
	bw.raw([]byte(a.Address))
	return buf.Bytes(), bw.err
}

type ObjectOwner struct {
	ParentId ObjectId
}

func (o *ObjectOwner) ownerKind() {}
func (o *ObjectOwner) serialize() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	bw := &binWriter{w: buf}
	bw.raw([]byte{ObjectOwnerHeader})
	bw.raw(o.ParentId[:])
	return buf.Bytes(), bw.err
}

// SharedOwner use same shared version present the address which be shared
type SharedOwner struct {
	SharedVersion uint64
}

func (s *SharedOwner) ownerKind() {}
func (s *SharedOwner) serialize() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 8+1))
	bw := &binWriter{w: buf}
	bw.raw([]byte{SharedOwnerHeader})
	bw.write(s.SharedVersion)
	return buf.Bytes(), bw.err
}

type ImmutableOwner struct{}

func (i *ImmutableOwner) ownerKind() {}
func (i *ImmutableOwner) serialize() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 1))
	bw := &binWriter{w: buf}
	bw.raw([]byte{ImmutableOwnerHeader})
	return buf.Bytes(), bw.err
}

const (
	MoveObjectHeader = 0x0A
	MoveModuleHeader = 0x0B
)

type ObjectData interface {
	getInformation() objectInformation
	Serialize() ([]byte, error)
}

type objectInformation struct {
	objectId ObjectId
	version  uint64
}

type MoveObject struct {
	ObjectId          ObjectId
	Version           uint64
	Type              string
	Contents          []byte
	HasPublicTransfer bool
}

func (m *MoveObject) getInformation() objectInformation {
	return objectInformation{
		objectId: m.ObjectId,
		version:  m.Version,
	}
}

func (m *MoveObject) Serialize() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	bw := &binWriter{w: buf}
	bw.raw([]byte{MoveObjectHeader})
	bw.write(m.ObjectId)
	bw.write(m.Version)
	typeBytes := []byte(m.Type)
	bw.write(uint32(len(typeBytes)))
	bw.raw(typeBytes)
	bw.write(uint32(len(m.Contents)))
	bw.raw(m.Contents)
	bw.write(m.HasPublicTransfer)

	if bw.err != nil {
		return nil, bw.err
	}

	return bw.w.Bytes(), nil
}

type MovePackage struct {
	ObjectId ObjectId
	Version  uint64
	Module   map[string][]byte
}

func (m *MovePackage) getInformation() objectInformation {
	return objectInformation{
		objectId: m.ObjectId,
		version:  m.Version,
	}
}

func (m *MovePackage) Serialize() ([]byte, error) {

	buf := bytes.NewBuffer(nil)
	bw := &binWriter{w: buf}
	bw.raw([]byte{MoveModuleHeader})
	bw.write(m.ObjectId)
	bw.write(m.Version)

	keys := slices.Sorted(maps.Keys(m.Module))
	bw.write(uint32(len(m.Module)))
	for _, k := range keys {
		bw.write(uint32(len(k)))
		bw.raw([]byte(k))
		bw.write(uint32(len(m.Module[k])))
		bw.raw(m.Module[k])
	}

	if bw.err != nil {
		return nil, bw.err
	}

	return bw.w.Bytes(), nil
}
