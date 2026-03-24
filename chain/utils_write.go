package chain

import (
	"bytes"
	"encoding/binary"
)

// TODO: move to util package not in chain
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
