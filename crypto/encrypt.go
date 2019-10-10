package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// EncryptBytes applies AES encryption to the data using the specified key
func EncryptBytes(data []byte, key string) (cipherdata []byte, err error) {
	return encrypt(data, key)
}

// EncryptMessage applies AES encryption to the text using the specified key
func EncryptMessage(data string, key string) (cipherdata []byte, err error) {
	return encrypt([]byte(data), key)
}

// GetPaddedLength returns the length of the padded data
func GetPaddedLength(data []byte) int {
	return len(data) + aes.BlockSize - (len(data) % aes.BlockSize) + aes.BlockSize
}

func encrypt(data []byte, key string) (cipherdata []byte, err error) {
	var (
		keyHash     [32]byte = sha256.Sum256([]byte(key))
		padZeros    int
		blockCipher cipher.Block
	)

	if padZeros = aes.BlockSize - (len(data) % aes.BlockSize); padZeros != 0 {
		padding := make([]byte, padZeros)
		data = append(data, padding...)
	}

	if blockCipher, err = aes.NewCipher(keyHash[:]); err != nil {
		return
	}

	cipherdata = make([]byte, aes.BlockSize+len(data))
	iv := cipherdata[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	mode := cipher.NewCBCEncrypter(blockCipher, iv)
	mode.CryptBlocks(cipherdata[aes.BlockSize:], data)
	return
}

// DecryptBytes applies AES decryption to the cipherdata using the specified key
func DecryptBytes(cipherdata []byte, key string) (data []byte, err error) {
	return decrypt(cipherdata, key)
}

// DecryptMessage applies AES decryption to the cipherdata using the specified key
func DecryptMessage(cipherdata []byte, key string) (text string, err error) {
	var data []byte
	data, err = decrypt(cipherdata, key)
	text = string(data)
	return
}

func decrypt(cipherdata []byte, key string) (data []byte, err error) {
	var (
		keyHash     [32]byte = sha256.Sum256([]byte(key))
		blockCipher cipher.Block
	)

	if len(cipherdata) < aes.BlockSize {
		err = errors.New("ciphertext too short")
		return
	}

	iv := cipherdata[:aes.BlockSize]
	data = cipherdata[aes.BlockSize:]

	if len(cipherdata)%aes.BlockSize != 0 {
		err = errors.New("ciphertext is not a multiple of the block size")
		return
	}

	if blockCipher, err = aes.NewCipher(keyHash[:]); err != nil {
		return
	}

	mode := cipher.NewCBCDecrypter(blockCipher, iv)
	mode.CryptBlocks(data, data)

	return
}
