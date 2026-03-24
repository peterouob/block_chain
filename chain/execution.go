package chain

import "errors"

type ExecutionEngin struct {
	Store ObjectStorer
}

type ExecutionEffect struct {
	Status            TransferStatus
	TransactionDigest Digest
	MutatedObjects    []MutatedObjects
	GasUsed           struct{}
}

type MutatedObjects struct {
	Before ObjectRef
	After  ObjectRef
}

var (
	ErrExecutionAddrInvalid      = errors.New("execution address invalid")
	ErrExecutionVersionNotEqual  = errors.New("execution version not equal")
	ErrExecutionObjectOwnerType  = errors.New("execution object owner type")
	ErrExecutionSenderNotTheSame = errors.New("execution sender not the same")
	ErrExecutionAssertFailed     = errors.New("execution assert failed")
)

func (e *ExecutionEngin) Execute(tx TransactionData, signature Signature, intentMsg []byte) (*ExecutionEffect, error) {
	effect := &ExecutionEffect{}
	address := signature.DecodeAddress()
	if address != tx.Sender {
		return nil, ErrExecutionAddrInvalid
	}

	if err := signature.Verify(intentMsg); err != nil {
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
	var err error

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
	effect.Status = TransferStatus{nil, true}
	effect.GasUsed = struct{}{}

	return effect, nil
}

type TransferStatus struct {
	err     error
	success bool
}
