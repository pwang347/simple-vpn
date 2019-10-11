package crypto

import (
	"encoding/binary"
	"math"
	"math/rand"
)

// TODO: handle key exchange here
const (
	// TODO: make these more interesting
	g                       uint64 = 6
	p                       uint64 = 17
	DefaultNonceLength             = 512
	DefaultPartialKeyLength        = 8
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
func GenerateRandomExponent() uint64 {
	buf := make([]byte, 8)
	rand.Read(buf) // Always succeeds, no need to check error
	return binary.LittleEndian.Uint64(buf)
}

func pow(x uint64, y uint64) uint64 {
	return uint64(math.Pow(float64(x), float64(y)))
}

// GeneratePartialKey generates a partial key
func GeneratePartialKey(exponent uint64) uint64 {
	return pow(g, exponent) % p
}

// ConstructKey constructs a shared key using the partial key and known exponent
func ConstructKey(partialKey uint64, knownExp uint64) uint64 {
	return pow(partialKey, knownExp) % p
}
