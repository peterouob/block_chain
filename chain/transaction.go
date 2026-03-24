package chain

import (
	"bytes"
	"errors"

	"golang.org/x/crypto/sha3"
)

type EpochId uint64

type TransactionData struct {
	Kind    TransactionKind
	Sender  Address
	GasData GasData
	Expire  TransactionExpirer
}

func NewTransactionData(sender Address, kind TransactionKind, gasData GasData, expire TransactionExpirer) *TransactionData {
	return &TransactionData{
		Sender:  sender,
		Kind:    kind,
		GasData: gasData,
		Expire:  expire,
	}
}

func (t *TransactionData) Serialize() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	bw := &binWriter{w: buf}

	kindBytes, err := t.Kind.serialize()
	if err != nil {
		return nil, err
	}
	bw.raw(kindBytes)

	senderBytes := []byte(t.Sender)
	bw.write(uint32(len(senderBytes)))
	bw.raw(senderBytes)

	gasBytes, err := t.GasData.Serialize()
	if err != nil {
		return nil, err
	}
	bw.raw(gasBytes)

	expireBytes, err := t.Expire.serialize()
	if err != nil {
		return nil, err
	}
	bw.raw(expireBytes)

	if bw.err != nil {
		return nil, bw.err
	}
	return buf.Bytes(), nil
}

func (t *TransactionData) Hash() (Digest, error) {
	b, err := t.Serialize()
	if err != nil {
		return Digest{}, err
	}
	return sha3.Sum256(b), nil
}

var (
	ErrTransactionSenderInvalid = errors.New("transaction sender invalid")
	ErrTransactionRecipient     = errors.New("transaction recipient invalid")
	ErrTransactionObjectInvalid = errors.New("transaction object invalid")
	ErrTransactionExpired       = errors.New("transaction expired")
)

func (t *TransactionData) Valid() error {
	if t.Sender == "" {
		return ErrTransactionSenderInvalid
	}

	if v, ok := t.Kind.(*ProgrammableTransaction); ok {
		for _, cmd := range v.Commands {
			switch c := cmd.(type) {
			case *TransferObject:
				if c.Recipient >= uint16(len(v.Inputs)) {
					return ErrTransactionRecipient
				}
				for _, obj := range c.Objects {
					if obj >= uint16(len(v.Inputs)) {
						return ErrTransactionObjectInvalid
					}
				}
			}
		}
	}

	if expire, ok := t.Expire.(*EpochExpire); ok && expire.EpochId == 0 {
		return ErrTransactionExpired
	}
	return nil
}

type GasData struct {
	Payments []ObjectRef
	Owner    Address
	Price    uint64
	Budget   uint64
}

func NewGasData(payments []ObjectRef, owner Address, price uint64, budget uint64) *GasData {
	return &GasData{
		Payments: payments,
		Owner:    owner,
		Price:    price,
		Budget:   budget,
	}
}

func (g *GasData) Serialize() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	bw := &binWriter{w: buf}

	bw.write(uint32(len(g.Payments)))
	for _, p := range g.Payments {
		bw.write(p.ObjectId)
		bw.write(p.Version)
		bw.write(p.Digest)
	}

	ownerBytes := []byte(g.Owner)
	bw.write(uint32(len(ownerBytes)))
	bw.raw(ownerBytes)

	bw.write(g.Price)
	bw.write(g.Budget)

	if bw.err != nil {
		return nil, bw.err
	}
	return buf.Bytes(), nil
}

const (
	NoneExpireHeader  = 0x10
	EpochExpireHeader = 0x11
)

type TransactionExpirer interface {
	expireType()
	serialize() ([]byte, error)
}

type NoneExpire struct{}

func (n NoneExpire) expireType() {}
func (n NoneExpire) serialize() ([]byte, error) {
	return []byte{NoneExpireHeader}, nil
}

type EpochExpire struct {
	EpochId EpochId
}

func (e EpochExpire) expireType() {}
func (e EpochExpire) serialize() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	bw := &binWriter{w: buf}
	bw.raw([]byte{EpochExpireHeader})
	bw.write(uint64(e.EpochId))
	if bw.err != nil {
		return nil, bw.err
	}
	return buf.Bytes(), nil
}

const (
	ProgrammableTransactionHeader = 0x20
)

type TransactionKind interface {
	transactionType()
	serialize() ([]byte, error)
}

type ProgrammableTransaction struct {
	Inputs   []CallArgs
	Commands []ProgramCommand
}

func NewProgrammableTransaction(inputs []CallArgs, commands []ProgramCommand) *ProgrammableTransaction {
	return &ProgrammableTransaction{
		Inputs:   inputs,
		Commands: commands,
	}
}

func (p *ProgrammableTransaction) transactionType() {}

func (p *ProgrammableTransaction) serialize() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	bw := &binWriter{w: buf}

	bw.raw([]byte{ProgrammableTransactionHeader})

	// Inputs: count + each CallArg
	bw.write(uint32(len(p.Inputs)))
	for _, input := range p.Inputs {
		inputBytes, err := input.serialize()
		if err != nil {
			return nil, err
		}
		bw.raw(inputBytes)
	}

	// Commands: count + each Command
	bw.write(uint32(len(p.Commands)))
	for _, cmd := range p.Commands {
		cmdBytes, err := cmd.serialize()
		if err != nil {
			return nil, err
		}
		bw.raw(cmdBytes)
	}

	if bw.err != nil {
		return nil, bw.err
	}
	return buf.Bytes(), nil
}

const (
	TransferObjectHeader = 0x30
)

type ProgramCommand interface {
	Command()
	serialize() ([]byte, error)
}

type TransferObject struct {
	Objects   []uint16
	Recipient uint16
}

func (t *TransferObject) Command() {}

func (t *TransferObject) serialize() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	bw := &binWriter{w: buf}

	bw.raw([]byte{TransferObjectHeader})

	bw.write(uint32(len(t.Objects)))
	for _, obj := range t.Objects {
		bw.write(obj)
	}

	bw.write(t.Recipient)

	if bw.err != nil {
		return nil, bw.err
	}
	return buf.Bytes(), nil
}

const (
	RefCallArgsHeader   = 0x40
	ValueCallArgsHeader = 0x41
)

type CallArgs interface {
	argsType()
	serialize() ([]byte, error)
}

type RefCallArgs struct {
	Ref ObjectRef
}

func (r *RefCallArgs) argsType() {}

func (r *RefCallArgs) serialize() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	bw := &binWriter{w: buf}

	bw.raw([]byte{RefCallArgsHeader})
	bw.write(r.Ref.ObjectId)
	bw.write(r.Ref.Version)
	bw.write(r.Ref.Digest)

	if bw.err != nil {
		return nil, bw.err
	}
	return buf.Bytes(), nil
}

type ValueCallArgs struct {
	Address Address
}

func (v *ValueCallArgs) argsType() {}

func (v *ValueCallArgs) serialize() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	bw := &binWriter{w: buf}

	bw.raw([]byte{ValueCallArgsHeader})
	addrBytes := []byte(v.Address)
	bw.write(uint32(len(addrBytes)))
	bw.raw(addrBytes)

	if bw.err != nil {
		return nil, bw.err
	}
	return buf.Bytes(), nil
}
