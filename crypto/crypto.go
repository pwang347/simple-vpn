package crypto

import (
	"encoding/gob"
	"math/rand"
	"time"
)

// Init seeds RNG and initializes cryptographic libraries
func Init() {
	rand.Seed(time.Now().UnixNano())
	gob.Register(AuthenticationPayloadBeginAB{})
	gob.Register(AuthenticationPayloadResponseBA{})
	gob.Register(AuthenticationPayloadResponseAB{})
}
