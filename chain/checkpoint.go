package chain

import (
	"bytes"
	"crypto/sha3"
)

type CheckPointContents struct {
	executionDigests []ExecutionDigests
}

func NewCheckPointContents(executionDigests []ExecutionDigests) CheckPointContents {
	return CheckPointContents{
		executionDigests: executionDigests,
	}
}

func (c CheckPointContents) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	bw := NewBinWriter(buf)

	bw.write(uint32(len(c.executionDigests)))

	for _, tx := range c.executionDigests {
		txRaw, err := tx.Serialize()
		if err != nil {
			return nil, err
		}
		bw.raw(txRaw)
	}

	return buf.Bytes(), nil
}

func (c CheckPointContents) Digest() (Digest, error) {
	buf, err := c.Serialize()
	if err != nil {
		return [32]byte{}, err
	}
	digest := sha3.Sum256(buf)
	return digest, nil
}

type CheckPointSummary struct {
	Epoch             uint64
	SequenceNumber    uint64
	TotalTransactions uint64
	ContentDigest     *Digest
	PrevDigest        *Digest
	TimeStamp         uint64
}

func (c CheckPointSummary) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	bw := NewBinWriter(buf)
	bw.write(c.Epoch)
	panic("implement me")
}

func (c CheckPointSummary) Digest() (Digest, error) {
	panic("implement me")
}

func (c CheckPointSummary) BCSBytes() ([]byte, error) {
	panic("implement me")
}
