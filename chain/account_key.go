package chain

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/dustinxie/ecc"
)

type p256k1PublicKey struct {
	Curve   string `json:"curve"`
	RawData []byte `json:"data"`
}

func newP256k1PublicKey(pub *ecdsa.PublicKey) p256k1PublicKey {
	data := make([]byte, 65)
	data[0] = 0x04

	pub.X.FillBytes(data[1:33])
	pub.Y.FillBytes(data[33:65])

	return p256k1PublicKey{
		Curve:   "P-256K1",
		RawData: data,
	}
}

func (p *p256k1PublicKey) X() []byte {
	return p.RawData[1:33]
}

func (p *p256k1PublicKey) Y() []byte {
	return p.RawData[33:65]
}

func (p *p256k1PublicKey) Compress() []byte {
	comp := make([]byte, 33)
	y := p.Y()
	comp[0] = 0x02 + (y[len(y)-1] & 0x01)
	copy(comp[1:], p.X())
	return comp
}

type p256k1PrivateKey struct {
	p256k1PublicKey
	D []byte `json:"d"`
}

func newP256k1PrivateKey(prev *ecdsa.PrivateKey) *p256k1PrivateKey {
	data := make([]byte, 32)
	prev.D.FillBytes(data)
	return &p256k1PrivateKey{
		p256k1PublicKey: newP256k1PublicKey(&prev.PublicKey),
		D:               data,
	}
}

func (p *p256k1PrivateKey) publicKey() *ecdsa.PublicKey {
	curve := ecc.P256k1()

	if len(p.RawData) != 65 || p.RawData[0] != 0x04 {
		panic("invalid public key")
	}

	x := new(big.Int).SetBytes(p.X())
	y := new(big.Int).SetBytes(p.Y())

	if !curve.IsOnCurve(x, y) {
		panic(fmt.Errorf("error the point isn't on curve"))
	}

	key := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return key
}

func (p *p256k1PrivateKey) privateKey() *ecdsa.PrivateKey {
	d := new(big.Int).SetBytes(p.D)
	return &ecdsa.PrivateKey{
		PublicKey: *p.publicKey(),
		D:         d,
	}
}

var (
	ErrInvalidLength   = errors.New("invalid length")
	ErrNoSupportPrefix = errors.New("no support prefix")
	ErrNotOnCurve      = errors.New("not on curve")
)

func DeCompressPubKey(pub []byte) (*big.Int, *big.Int, error) {
	if len(pub) != 33 {
		return nil, nil, ErrInvalidLength
	}

	if pub[0] != 0x02 && pub[0] != 0x03 {
		return nil, nil, ErrNoSupportPrefix
	}

	x := new(big.Int).SetBytes(pub[1:])
	curve := ecc.P256k1()
	P := curve.Params().P

	// x^3+7 = y^3
	x3 := new(big.Int).Exp(x, big.NewInt(3), P)
	ySQ := new(big.Int).Add(x3, big.NewInt(7))
	ySQMod := new(big.Int).Mod(ySQ, P)

	ex := new(big.Int).Add(P, big.NewInt(1))
	ex.Div(ex, big.NewInt(4))
	y := new(big.Int).Exp(ySQMod, ex, P)

	if (y.Bit(0) == 1) != (pub[0] == 0x03) {
		y.Sub(P, y)
	}

	if !curve.IsOnCurve(x, y) {
		return nil, nil, ErrNotOnCurve
	}

	return x, y, nil
}
