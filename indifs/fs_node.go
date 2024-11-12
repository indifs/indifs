package indifs

import (
	"github.com/indifs/indifs/crypto"
	"strings"
)

type fsNode struct {
	Header   Header
	path     string
	children []*fsNode
}

func indexTree(hh []Header) (tree map[string]*fsNode, err error) {
	tree = make(map[string]*fsNode, len(hh))
	for _, h := range hh {
		path := h.Path()
		if tree[path] != nil { // can`t repeat
			return nil, errSeveralNodes
		}
		nd := &fsNode{Header: h, path: path}
		tree[path] = nd
		if path == "/" {
			continue
		}
		if p := tree[dirname(path)]; p == nil { // find parent node
			return nil, errParentDirNotFound
		} else if p.Header.Deleted() {
			return nil, errParentDirIsDeleted
		} else {
			p.children = append(p.children, nd)
		}
	}
	return
}

func (nd *fsNode) copyChildHeaders() []Header {
	hh := make([]Header, len(nd.children))
	for i, c := range nd.children {
		hh[i] = c.Header.Copy()
	}
	return hh
}

func (nd *fsNode) walk(fn func(nd *fsNode) bool) {
	if nd != nil && fn(nd) {
		for _, c := range nd.children {
			c.walk(fn)
		}
	}
}

func (nd *fsNode) deleted() bool {
	return nd != nil && nd.Header.Deleted()
}

func (nd *fsNode) isDir() bool {
	return strings.HasSuffix(nd.path, "/")
}

func (nd *fsNode) hasFile(path string) bool {
	return nd.path == path || nd.isDir() && strings.HasPrefix(path, nd.path)
}

func (nd *fsNode) merkleRoot() []byte {
	if len(nd.children) == 0 {
		return nd.Header.Hash()
	}
	return crypto.MerkleRoot(nd.Header.Hash(), nd.childrenMerkleRoot())
}

func (nd *fsNode) merkleWitness(path string) []byte {
	if nd.path == path {
		if len(nd.children) == 0 { // is file or empty dir
			return nd.Header.Hash()
		}
		return crypto.MakeMerkleWitness([][]byte{ // is dir
			nd.Header.Hash(),
			nd.childrenMerkleRoot(),
		}, 0)
	}
	return crypto.MerkleWitnessAppend(
		nd.childrenMerkleWitness(path),
		crypto.OpLHash,
		nd.Header.Hash(),
	)
}

func (nd *fsNode) totalVolume() (n int64) {
	if nd.path != "/" { // exclude root
		n += nd.Header.totalVolume()
	}
	for _, c := range nd.children {
		n += c.totalVolume()
	}
	return n
}

func (nd *fsNode) childrenMerkleRoot() []byte {
	return crypto.MakeMerkleRoot(len(nd.children), func(i int) []byte {
		return nd.children[i].merkleRoot()
	})
}

func (nd *fsNode) childrenMerkleWitness(path string) []byte {
	var hashes [][]byte
	var iHash int
	for i, sub := range nd.children {
		if sub.hasFile(path) {
			iHash = i
			hashes = append(hashes, sub.merkleWitness(path))
		} else {
			hashes = append(hashes, sub.merkleRoot())
		}
	}
	return crypto.MakeMerkleWitness(hashes, iHash)
}
