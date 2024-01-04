package crypto

import (
	"crypto/sha256"
	"hash"
)

// HashSize is the size of a hash-checksum in bytes.
const HashSize = 32

// NewHash returns a new hash.Hash computing the SHA256 checksum.
func NewHash() hash.Hash {
	return sha256.New()
}

// Hash returns the SHA256 checksum of concatenated arguments.
func Hash(vv ...[]byte) []byte {
	h := NewHash()
	for _, v := range vv {
		h.Write(v)
	}
	return h.Sum(nil)
}
