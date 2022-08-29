package jwk

import (
	"math/big"
	"testing"
)

func FuzzEncodeDecodeCoord(f *testing.F) {
	f.Fuzz(func(t *testing.T, coord []byte) {
		coordB := big.NewInt(0).SetBytes(coord)
		encoded := encodeCoord(len(coord), coordB)
		decoded, err := decodeCoord(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Cmp(coordB) != 0 {
			t.Fatal("not equal")
		}
	})
}
