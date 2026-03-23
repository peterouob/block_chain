package trnasaction

import "github.com/peterouob/block_chain/chain/object"

type ExecutionEngineer interface {
	VerifySignature(signature []byte, data []byte) error
	CheckOwner(owner object.Owner, data []byte) error
	ExecuteCommands(command []ProgramCommand)
}

type ExecutionEngin struct{}
