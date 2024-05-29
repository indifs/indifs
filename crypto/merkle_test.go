package crypto

import (
	"encoding/hex"
	"io"
	"math/rand"
	"testing"
)

func TestNewMerkleHash(t *testing.T) {

	const partSize = 1 << 20 // 1MiB
	hash := NewMerkleHash(partSize)

	// write random data
	n, err := io.Copy(hash, io.LimitReader(rand.New(rand.NewSource(0)), 20e6))

	assert(t, n == 20e6)
	assert(t, err == nil)
	assert(t, len(hash.Leaves()) == 20)
	assert(t, hex.EncodeToString(hash.Root()) == "1504aceff010d04d5ee597bf33d2195491d3534b5e28e9c08259bc4d50373490")
}

func TestNewMerkleHash_withZero(t *testing.T) {

	hash := NewMerkleHash(0) // is equivalent of NewHash()

	// write random data
	n, err := io.Copy(hash, io.LimitReader(rand.New(rand.NewSource(0)), 20e6))

	assert(t, n == 20e6)
	assert(t, err == nil)
	assert(t, len(hash.Leaves()) == 1)
	assert(t, hex.EncodeToString(hash.Root()) == "9c9f54aca340d76dd36acd53069805bed7aca84f28b1a6bc2c7d27f7f06fac20")
}

func TestNewHash(t *testing.T) {

	hash := NewHash()

	// write random data
	n, err := io.Copy(hash, io.LimitReader(rand.New(rand.NewSource(0)), 20e6))

	assert(t, n == 20e6)
	assert(t, err == nil)
	assert(t, hex.EncodeToString(hash.Sum(nil)) == "9c9f54aca340d76dd36acd53069805bed7aca84f28b1a6bc2c7d27f7f06fac20")
}
