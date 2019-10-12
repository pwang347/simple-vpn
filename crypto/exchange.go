package crypto

import (
	"math/big"
	"math/rand"
)

const (
	// DefaultNonceLength is the length of the default nonce
	DefaultNonceLength = 512

	// DefaultPartialKeyLength is the length of the default partial key
	DefaultPartialKeyLength = 64

	// DefaultExponentLength is the length of the default exponent
	DefaultExponentLength = 64
)

// see https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#algspec
var (
	g = [64]byte{
		0x61, 0x84, 0x71, 0xb2,
		0x7a, 0x9c, 0xf4, 0x4e,
		0xe9, 0x1a, 0x49, 0xc5,
		0x14, 0x7d, 0xb1, 0xa9,
		0xaa, 0xf2, 0x44, 0xf0,
		0x5a, 0x43, 0x4d, 0x64,
		0x86, 0x93, 0x1d, 0x2d,
		0x14, 0x27, 0x1b, 0x9e,
		0x35, 0x03, 0x0b, 0x71,
		0xfd, 0x73, 0xda, 0x17,
		0x90, 0x69, 0xb3, 0x2e,
		0x29, 0x35, 0x63, 0x0e,
		0x1c, 0x20, 0x62, 0x35,
		0x4d, 0x0d, 0xa2, 0x0a,
		0x6c, 0x41, 0x6e, 0x50,
		0xbe, 0x79, 0x4c, 0xa4,
	}
	p = [DefaultPartialKeyLength]byte{
		0xfc, 0xa6, 0x82, 0xce,
		0x8e, 0x12, 0xca, 0xba,
		0x26, 0xef, 0xcc, 0xf7,
		0x11, 0x0e, 0x52, 0x6d,
		0xb0, 0x78, 0xb0, 0x5e,
		0xde, 0xcb, 0xcd, 0x1e,
		0xb4, 0xa2, 0x08, 0xf3,
		0xae, 0x16, 0x17, 0xae,
		0x01, 0xf3, 0x5b, 0x91,
		0xa4, 0x7e, 0x6d, 0xf6,
		0x34, 0x13, 0xc5, 0xe1,
		0x2e, 0xd0, 0x89, 0x9b,
		0xcd, 0x13, 0x2a, 0xcd,
		0x50, 0xd9, 0x91, 0x51,
		0xbd, 0xc4, 0x3e, 0xe7,
		0x37, 0x59, 0x2e, 0x17,
	}
)

// AuthenticationPayloadBeginAB is the message format for the first step of authentication
type AuthenticationPayloadBeginAB struct {
	ChallengeAB [DefaultNonceLength]byte
}

// AuthenticationPayloadResponseBA is the message format for the second step of authentication
type AuthenticationPayloadResponseBA struct {
	ChallengeBA                   [DefaultNonceLength]byte
	EncSrvrChallengeABPartialkeyB []byte
}

// AuthenticationPayloadResponseAB is the message format for the third step of authentication
type AuthenticationPayloadResponseAB struct {
	EncChallengeBAPartialKeyA []byte
}

// DecodedChallengePartialKey is the decoded challenge key appended to the partial key
type DecodedChallengePartialKey struct {
	Challenge  [DefaultNonceLength]byte
	PartialKey [DefaultPartialKeyLength]byte
}

// DecodedSrvrChallengePartialKey is the decoded literal SRVR, appended to the challenge key and the partial key
type DecodedSrvrChallengePartialKey struct {
	SRVR       [4]byte
	Challenge  [DefaultNonceLength]byte
	PartialKey [DefaultPartialKeyLength]byte
}

// NewChallenge generates a new challenge of size bytes
func NewChallenge(size int) []byte {
	token := make([]byte, size)
	rand.Read(token)
	return token
}

// GenerateRandomExponent generates a random exponent
func GenerateRandomExponent() (exponent []byte) {
	exponent = make([]byte, DefaultExponentLength)
	rand.Read(exponent) // Always succeeds, no need to check error
	return
}

func bpow(x []byte, y []byte, m []byte) []byte {
	xNum := new(big.Int)
	xNum.SetBytes(x)
	yNum := new(big.Int)
	yNum.SetBytes(y)
	mNum := new(big.Int)
	mNum.SetBytes(m)
	return xNum.Exp(xNum, yNum, mNum).Bytes()
}

// GeneratePartialKey generates a partial key
func GeneratePartialKey(exponent []byte) []byte {
	return bpow(g[:], exponent, p[:])
}

// ConstructKey constructs a shared key using the partial key and known exponent
func ConstructKey(partialKey []byte, exponent []byte) []byte {
	return bpow(partialKey, exponent, p[:])
}

// BytesToBigNumString returns the string representation of the big num
func BytesToBigNumString(x []byte) string {
	xNum := new(big.Int)
	xNum.SetBytes(x)
	return xNum.String()
}
