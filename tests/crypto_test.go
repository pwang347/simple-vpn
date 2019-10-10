package tests

import (
	"bytes"
	"testing"

	"github.com/Gordon-Yeh/simple-vpn/crypto"
)

// TestEncryptDecrypt tests that encrypt / decrypt is working as intended
func TestEncryptDecrypt(t *testing.T) {
	var (
		encrypted []byte
		decrypted []byte
		err       error
	)
	data := []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12}
	key := "s3cr3t"
	if encrypted, err = crypto.EncryptBytes(data, key); err != nil {
		t.Errorf(err.Error())
	}

	if len(encrypted) != crypto.GetPaddedLength(data) {
		t.Errorf("Expected encrypted size to be %d, was %d\n", crypto.GetPaddedLength(data), len(encrypted))
	}

	if decrypted, err = crypto.DecryptBytes(encrypted, key); err != nil {
		t.Errorf(err.Error())
	}

	decrypted = decrypted[:len(data)]
	if !bytes.Equal(decrypted, data) {
		t.Errorf("Expected was %s, decrypted was %s\n", data, decrypted)
	}
}
