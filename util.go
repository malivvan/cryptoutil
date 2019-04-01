package cryptoutil

import (
	"math/rand"
	"time"
)

func randomInt(min, max int) int {
	rand.Seed(time.Now().Unix())
	return rand.Intn(max-min) + min
}

