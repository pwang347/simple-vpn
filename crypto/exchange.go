package crypto

import (
	"math"
	"math/rand"
	"time"
)

// TODO: handle key exchange here
const (
	g int = 6
	p int = 17
)

func NewChallenge() int {
	// FIXME: not cryptographically secure
	var s = rand.NewSource(time.Now().UnixNano())
	var r = rand.New(s)
	return r.Int()
}

func pow(x int, y int) int {
	return int(math.Pow(float64(x), float64(y)))
}

func GeneratePartialKey(exponent int) int {
	return pow(g, exponent) % p
}

func GenerateKey(partialKey int, knownExp int) int {
	return pow(partialKey, knownExp) % p
}
