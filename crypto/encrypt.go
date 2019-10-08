package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"strconv"
	"strings"
)

// TODO: handle encryption etc here
func Encrypt(nonce int, partialKey int, key string) []byte {
	return encryptAES(strconv.Itoa(nonce)+" "+strconv.Itoa(partialKey), key)
}

func encryptAES(plaintext string, key string) []byte {
	var (
		keyHash     [32]byte = sha256.Sum256([]byte(key))
		plainBuf    []byte   = []byte(plaintext)
		padZeros    int
		blockCipher cipher.Block
		err         error
	)
	if padZeros = aes.BlockSize - (len(plainBuf) % aes.BlockSize); padZeros != 0 {
		plainBuf = []byte(strings.Repeat("0", padZeros) + plaintext)
	}
	if blockCipher, err = aes.NewCipher(keyHash[:]); err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plainBuf))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(blockCipher, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plainBuf)

	// fmt.Println("plaintext: ")
	// fmt.Println(string(plainBuf))
	// fmt.Println(len(plainBuf))
	// fmt.Println("ciphertext: ")
	// fmt.Println(string(ciphertext))
	// fmt.Println(len(ciphertext))
	return ciphertext
}

// func DecryptString(ciphertext string, key string) string {
// 	return string(Decrypt([]byte(ciphertext), []byte(key)))
// }

func Decrypt(ciphertext []byte, key []byte) []byte {
	var (
		keyHash     [32]byte = sha256.Sum256(key)
		cipherBuf   []byte   = ciphertext
		blockCipher cipher.Block
		err         error
	)
	// fmt.Println("DECRYPTING...")
	// fmt.Println(ciphertext)
	// fmt.Println(len(cipherBuf))
	if len(cipherBuf) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := cipherBuf[:aes.BlockSize]
	cipherBuf = cipherBuf[aes.BlockSize:]

	if len(cipherBuf)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	if blockCipher, err = aes.NewCipher(keyHash[:]); err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(blockCipher, iv)
	mode.CryptBlocks(cipherBuf, cipherBuf)
	return cipherBuf
}
