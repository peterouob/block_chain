package chain

import (
	"bytes"
	"encoding/binary"
)

type DataType interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 |
		~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~float32 | ~float64 | ~[32]byte | bool
}

// TODO: move to util package not in chain
type BinWriter struct {
	w   *bytes.Buffer
	err error
}

func NewBinWriter(buf *bytes.Buffer) *BinWriter {
	return &BinWriter{w: buf}
}

// write is for the len of a byte array or the type which don't include size
func (bw *BinWriter) write[T DataType](data T) {
	if bw.err != nil {
		return
	}
	bw.err = binary.Write(bw.w, binary.LittleEndian, data)
}

func (bw *BinWriter) raw(p []byte) {
	if bw.err != nil {
		return
	}
	_, bw.err = bw.w.Write(p)
}
