package crypto

import (
	"bytes"
	"hash"
	"math"
	"math/bits"
)

// OpLHash and OpRHash are the operations for the merkle-proof.
const (
	OpLHash = 0
	OpRHash = 1
)

// MerkleHash is an interface for computing the merkle-root of a stream of data.
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

// NewMerkleHash creates a new MerkleHash with the specified part size.
func NewMerkleHash(partSize int64) MerkleHash {
	if partSize <= 0 {
		partSize = math.MaxInt64
	}
	return &merkleHash{
		partSize: partSize,
		hash:     NewHash(),
	}
}

// Write writes data to the merkle-hash.
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

// Root returns the merkle-root of the written data.
func (h *merkleHash) Root() []byte {
	return MerkleRoot(h.Leaves()...)
}

// Written returns the total number of bytes written.
func (h *merkleHash) Written() int64 {
	return h.n
}

// Leaves returns the leaves of the merkle-tree.
func (h *merkleHash) Leaves() [][]byte {
	if h.nHash > 0 {
		h.parts, h.nHash = append(h.parts, h.hash.Sum(nil)), 0
		h.hash.Reset()
	}
	return h.parts
}

// MerkleRoot computes the merkle-root from the given hashes.
func MerkleRoot(hash ...[]byte) []byte {
	return MakeMerkleRoot(len(hash), func(i int) []byte {
		return hash[i]
	})
}

// MakeMerkleRoot computes the merkle-root from the given number of items and their hashes.
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

// MakeMerkleProof creates a merkle-proof for the given index in the list of hashes.
func MakeMerkleProof(hashes [][]byte, i int) []byte {
	n := len(hashes)
	if i < 0 || i >= n {
		panic("MakeMerkleProof-error: invalid tree index")
	}
	if n == 1 {
		return nil
	}
	if i2 := merkleMiddle(n); i < i2 { // arg=HASH(arg|op)
		return AppendMerkleProof(
			MakeMerkleProof(hashes[:i2], i),
			OpRHash,
			MerkleRoot(hashes[i2:]...),
		)
	} else { // arg=HASH(op|arg)
		return AppendMerkleProof(
			MakeMerkleProof(hashes[i2:], i-i2),
			OpLHash,
			MerkleRoot(hashes[:i2]...),
		)
	}
}

// AppendMerkleProof appends operation and a hash to the merkle-proof.
func AppendMerkleProof(proof []byte, op byte, hash []byte) []byte {
	if len(hash) == 0 {
		return proof
	}
	return append(append(proof, op), hash...)
}

func merkleMiddle(n int) int {
	if n <= 1 {
		return 0
	}
	return 1 << (bits.Len(uint(n-1)) - 1)
}

// VerifyMerkleProof verifies the merkle-proof for the given hash and root.
func VerifyMerkleProof(hash, root, proof []byte) bool {
	const opSize = HashSize + 1
	for n := len(proof); n > 0; n -= opSize {
		if n < opSize {
			return false
		}
		switch op, arg := proof[0], proof[1:opSize]; op {
		case OpRHash:
			hash = Hash(hash, arg)
		case OpLHash:
			hash = Hash(arg, hash)
		default:
			return false
		}
		proof = proof[opSize:]
	}
	return bytes.Equal(hash, root)
}
