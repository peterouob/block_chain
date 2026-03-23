package chain

import (
	"errors"
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

var (
	ErrTransactionSenderInvalid  = errors.New("transaction sender invalid")
	ErrTransactionProgramInvalid = errors.New("transaction program invalid")
	ErrTransactionExpired        = errors.New("transaction expired")
)

func (t *TransactionData) Valid() error {
	if t.Sender == "" {
		return ErrTransactionSenderInvalid
	}

	if program, ok := t.Kind.(*ProgrammableTransaction); ok &&
		program.Inputs == nil ||
		program.Commands == nil ||
		(program.Inputs != nil &&
			program.Commands != nil &&
			len(program.Inputs) != len(program.Commands)) {
		return ErrTransactionProgramInvalid
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

type TransactionExpirer interface {
	expireType()
}

type NoneExpire struct{}

func (n NoneExpire) expireType() {}

type EpochExpire struct {
	EpochId EpochId
}

func (e EpochExpire) expireType() {}

type TransactionKind interface {
	transactionType()
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

func (p ProgrammableTransaction) transactionType() {}

type ProgramCommand interface {
	Command()
}

type TransferObject struct {
	Objects   []uint16
	Recipient uint16
}

func (t TransferObject) Command() {}

type CallArgs interface {
	argsType()
}

type RefCallArgs struct {
	Ref ObjectRef
}

func (r RefCallArgs) argsType() {}

type ValueCallArgs struct {
	Address Address
}

func (v ValueCallArgs) argsType() {}
