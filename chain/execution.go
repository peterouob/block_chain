package chain

type ExecutionEngineer interface {
	VerifySignature(signature []byte, data []byte) error
	CheckOwner(owner Owner, data []byte) error
	ExecuteCommands(command []ProgramCommand)
}

type ExecutionEngin struct{}
