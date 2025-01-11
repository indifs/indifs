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
	require(len(hh) > 0 && hh[0].IsRoot(), "indexTree-error")
	tree = make(map[string]*fsNode, len(hh))
	tree[""] = &fsNode{Header: hh[0]}
	for _, h := range hh[1:] {
		path := h.Path()
		if tree[path] != nil { // can`t repeat
			return nil, errSeveralNodes
		}
		nd := &fsNode{Header: h, path: path}
		tree[path] = nd
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

func (nd *fsNode) isRoot() bool {
	return nd.path == ""
}

func (nd *fsNode) isDir() bool {
	return isDir(nd.path)
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

func (nd *fsNode) merkleProof(path string) []byte {
	if nd.path == path {
		return crypto.AppendMerkleProof(
			nil,
			crypto.OpRHash,
			nd.childrenMerkleRoot(),
		)
	}
	return crypto.AppendMerkleProof(
		nd.childrenMerkleProof(path),
		crypto.OpLHash,
		nd.Header.Hash(),
	)
}

func (nd *fsNode) totalVolume() (n int64) {
	if nd.path != "" { // exclude root
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

func (nd *fsNode) childrenMerkleProof(path string) []byte {
	var hashes [][]byte
	var iHash int
	for i, sub := range nd.children {
		if sub.hasFile(path) {
			iHash = i
			hashes = append(hashes, sub.merkleProof(path))
		} else {
			hashes = append(hashes, sub.merkleRoot())
		}
	}
	return append(hashes[iHash], crypto.MakeMerkleProof(hashes, iHash)...)
}
