package jwk

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"strings"
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

func FuzzEncodeDecodePublicKey(f *testing.F) {
	f.Add(elliptic.P224().Params().Name, "0")
	f.Add(elliptic.P256().Params().Name, "0")
	f.Add(elliptic.P384().Params().Name, "0")
	f.Add(elliptic.P521().Params().Name, "0")
	f.Fuzz(func(t *testing.T, curveName string, keyID string) {
		keyID = strings.ToValidUTF8(keyID, "")
		curve, err := curveByName(curveName)
		if err != nil {
			return
		}
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publicKey := privateKey.PublicKey

		buf := bytes.Buffer{}
		if err := EncodePublicKey(&buf, keyID, publicKey); err != nil {
			t.Fatal(err)
		}

		keyID2, publicKey2, err := DecodePublicKey(buf.String())
		if err != nil {
			t.Fatal(err)
		}
		if keyID != keyID2 {
			t.Fatalf("%s != %s", keyID, keyID2)
		}
		if !publicKey.Equal(publicKey2) {
			t.Fatalf("%+v != %+v", publicKey, publicKey2)
		}

	})
}
