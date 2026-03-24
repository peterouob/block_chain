package chain

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/dustinxie/ecc"
)

func ByteToPubKey(pub []byte) *ecdsa.PublicKey {
	curve := ecc.P256k1()
	x, y, err := DeCompressPubKey(pub)
	if err != nil {
		return nil
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
}

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
