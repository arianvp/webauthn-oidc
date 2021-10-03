package webauthn

import (
	"bytes"
	"crypto/sha256"
	"log"
	"testing"
)

func TestAuthenticatorData(t *testing.T) {
	rpIDHash := sha256.Sum256([]byte("hello"))
	flags := FlagUserPresent | FlagUserPresent
	// count := uint32(293293)

	buf := make([]byte, 0, 37)
	buf = append(buf, rpIDHash[:]...)
	buf = append(buf, byte(flags))
	buf = append(buf, []byte{0xa, 0xb, 0xc, 0xd}...)
	buf = append(buf, []byte{123, 232, 23}...)
	// binary.BigEndian.PutUint32(bytes[33:], count)

	var data AuthenticatorData
	if err := ReadAuthenticatorData(bytes.NewReader(buf), &data); err != nil {
		log.Fatal(err)
	}

	if data.RPIDHash != rpIDHash {
		log.Fatalf("rpID mismatch")
	}
	if data.Flags != flags {
		log.Fatalf("flag mismatch")
	}
	if data.Count != 0x0a0b0c0d {
		log.Fatalf("count mismatch")
	}

	bufWriter := new(bytes.Buffer)
	if err := WriteAuthenticatorData(bufWriter, &data); err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(bufWriter.Bytes(), buf) {
		log.Fatalf("bytes didn't match")
	}

}
