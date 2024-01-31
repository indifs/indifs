package crypto

import (
	"bytes"
	"hash"
	"math"
)

const (
	OpLHash = 0
	OpRHash = 1
)

type MerkleHash interface {
	Write([]byte) (n int, err error)
	Root() []byte
	Written() int64
	Leaves() [][]byte
}

type merkleHash struct {
	partSize int64
	n        int64
	hash     hash.Hash
	nHash    int64
	parts    [][]byte
}

func NewMerkleHash(partSize int64) MerkleHash {
	if partSize <= 0 {
		partSize = math.MaxInt64
	}
	return &merkleHash{
		partSize: partSize,
		hash:     NewHash(),
	}
}

func (h *merkleHash) Write(data []byte) (n int, err error) {
	n = len(data)
	h.n += int64(n)
	for nBuf := int64(n); h.nHash+nBuf >= h.partSize; {
		n1 := h.partSize - h.nHash
		h.hash.Write(data[:n1])
		nBuf -= n1
		data = data[n1:]
		h.parts, h.nHash = append(h.parts, h.hash.Sum(nil)), 0
		h.hash.Reset()
	}
	h.hash.Write(data)
	h.nHash += int64(len(data))
	return
}

func (h *merkleHash) Root() []byte {
	return MerkleRoot(h.Leaves()...)
}

func (h *merkleHash) Written() int64 {
	return h.n
}

func (h *merkleHash) Leaves() [][]byte {
	if h.nHash > 0 {
		h.parts, h.nHash = append(h.parts, h.hash.Sum(nil)), 0
		h.hash.Reset()
	}
	return h.parts
}

func MerkleRoot(hash ...[]byte) []byte {
	return MakeMerkleRoot(len(hash), func(i int) []byte {
		return hash[i]
	})
}

func MakeMerkleRoot(n int, itemHash func(int) []byte) []byte {
	return merkleRootFn(0, n, itemHash)
}

func merkleRootFn(offset, n int, itemHash func(int) []byte) []byte {
	if n == 0 {
		return nil
	} else if n == 1 {
		return itemHash(offset)
	}
	i := merkleMiddle(n)
	return Hash(
		merkleRootFn(offset, i, itemHash),
		merkleRootFn(offset+i, n-i, itemHash),
	)
}

func MakeMerkleWitness(hashes [][]byte, i int) (buf []byte) {
	n := len(hashes)
	if i < 0 || i >= n {
		panic("invalid tree")
	}
	if n == 1 {
		return hashes[0]
	}
	if i2 := merkleMiddle(n); i < i2 { // arg=HASH(arg|op)
		return MerkleWitnessAppend(
			MakeMerkleWitness(hashes[:i2], i),
			OpRHash,
			MerkleRoot(hashes[i2:]...),
		)
	} else { // arg=HASH(op|arg)
		return MerkleWitnessAppend(
			MakeMerkleWitness(hashes[i2:], i-i2),
			OpLHash,
			MerkleRoot(hashes[:i2]...),
		)
	}
}

func MerkleWitnessAppend(witness []byte, op byte, hash []byte) []byte {
	return append(append(witness, op), hash...)
}

func merkleMiddle(n int) (i int) {
	for i = 1; i < n; i <<= 1 {
	}
	return i >> 1
}

func VerifyMerkleWitness(hash, root, witness []byte) bool {
	const opSize = HashSize + 1
	for n := len(witness); n > 0; n -= opSize {
		if n < opSize {
			return false
		}
		switch op, arg := witness[0], witness[1:opSize]; op {
		case OpRHash:
			hash = Hash(hash, arg)
		case OpLHash:
			hash = Hash(arg, hash)
		default:
			return false
		}
		witness = witness[opSize:]
	}
	return bytes.Equal(hash, root)
}
