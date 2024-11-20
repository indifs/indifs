package indifs

import (
	"bytes"
	"github.com/indifs/indifs/crypto"
	"github.com/indifs/indifs/db"
	"io"
	"sync"
)

type fileSystem struct {
	pub   crypto.PublicKey
	db    db.Storage
	mx    sync.RWMutex
	nodes map[string]*fsNode
}

const dbKeyHeaders = "."

func OpenFS(pub crypto.PublicKey, db db.Storage) (_ IFS, err error) {
	defer recoverError(&err)
	s := &fileSystem{
		pub: pub,
		db:  db,
	}
	s.initDB()
	return s, nil
}

func (f *fileSystem) rootNode() *fsNode {
	return f.nodes[""]
}

func (f *fileSystem) setPartSize(size int64) {
	f.rootNode().Header.SetInt(headerFilePartSize, size)
}

//func (f *fileSystem) PublicKey() crypto.PublicKey {
//	return f.pub
//}

func (f *fileSystem) headers() (hh []Header) {
	hh = make([]Header, 0, len(f.nodes))
	for _, nd := range f.nodes {
		hh = append(hh, nd.Header)
	}
	sortHeaders(hh)
	return
}

func (f *fileSystem) Trace() {
	traceHeaders(f.headers())
}

func (f *fileSystem) initDB() {
	var hh []Header
	mustOK(db.GetJSON(f.db, dbKeyHeaders, &hh))
	if hh == nil { // empty db
		hh = []Header{NewRootHeader(f.pub)}
	}
	f.nodes = mustVal(indexTree(hh))
}

func (f *fileSystem) fileHeader(path string) Header {
	if nd := f.nodes[path]; nd != nil {
		return nd.Header
	}
	return nil
}

func (f *fileSystem) Root() Header {
	return f.rootNode().Header
}

func (f *fileSystem) FileHeader(path string) (Header, error) {
	f.mx.RLock()
	defer f.mx.RUnlock()

	if h := f.fileHeader(path); h != nil {
		return h.Copy(), nil
	}
	return nil, ErrNotFound
}

func (f *fileSystem) FileMerkleWitness(path string) (hash, witness []byte, err error) {
	f.mx.RLock()
	defer f.mx.RUnlock()

	if f.nodes[path] == nil {
		return nil, nil, ErrNotFound
	}
	witness = f.rootNode().childrenMerkleWitness(path)
	return witness[:crypto.HashSize], witness[crypto.HashSize:], nil
}

func (f *fileSystem) rootPartSize() int64 {
	if size := f.Root().PartSize(); size > 0 {
		return size
	}
	return DefaultFilePartSize
}

func (f *fileSystem) FileParts(path string) (hashes [][]byte, err error) {
	f.mx.RLock()
	defer f.mx.RUnlock()

	h := f.fileHeader(path)
	if h == nil {
		return nil, ErrNotFound
	}
	fl, err := f.db.Open(path)
	if err != nil {
		return
	}
	defer fl.Close()

	partSize := h.PartSize()
	if partSize == 0 {
		partSize = f.rootPartSize()
	}
	w := crypto.NewMerkleHash(partSize)
	if _, err = io.Copy(w, fl); err != nil {
		return
	}
	return w.Leaves(), nil
}

func (f *fileSystem) Open(path string) (io.ReadSeekCloser, error) {
	return f.db.Open(path)
}

func (f *fileSystem) OpenAt(path string, offset int64) (io.ReadCloser, error) {
	r, err := f.db.Open(path)
	if err != nil {
		return nil, err
	}
	if _, err = r.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	return r, nil
}

//func (f *fileSystem) FileContent(path string, offset int64, size int) (data []byte, err error) {
//	data, err = f.db.Get(path)
//	if err == nil {
//		data = data[offset : int(offset)+size]
//	}
//	return
//}

func (f *fileSystem) ReadDir(path string) ([]Header, error) {
	f.mx.RLock()
	defer f.mx.RUnlock()

	if d := f.nodes[path]; d != nil && d.isDir() && !d.deleted() {
		return d.copyChildHeaders(), nil
	}
	return nil, ErrNotFound
}

func (f *fileSystem) Get(req string) (commit *Commit, err error) {
	f.mx.RLock()
	defer f.mx.RUnlock()

	return
}

func (f *fileSystem) GetCommit(ver int64) (commit *Commit, err error) {
	f.mx.RLock()
	defer f.mx.RUnlock()
	defer recoverError(&err)

	root := f.rootNode()
	if root.Header.Ver() <= ver {
		return
	}
	w := newFilesReader()
	commit = &Commit{Body: w}
	root.walk(func(nd *fsNode) bool {
		if h := nd.Header; h.Ver() > ver {
			commit.Headers = append(commit.Headers, h.Copy())

			// TODO: rr[] = f.getReader(path) ...;  commit.Body = io.MultiReader(rr...)
			if size := h.FileSize(); size > 0 { // write file content to commit-body
				w.add(func() (io.ReadCloser, error) {
					return f.Open(nd.path)
				})
			}
		}
		return true
	})
	return
}

func (f *fileSystem) Commit(commit *Commit) (err error) {
	defer recoverError(&err)
	f.mx.Lock()
	defer f.mx.Unlock()

	//--- verify commit ---
	require(len(commit.Headers) > 0, "empty commit")
	sortHeaders(commit.Headers)

	//--- verify root-header ---
	r := f.Root()
	c := commit.Root() // commit.Headers[0]

	require(protocolVerMajor(c.Get(headerProtocol)) == protocolVerMajor(DefaultProtocol), "unsupported Protocol version")
	require(protocolVer64(c.Get(headerProtocol)) >= protocolVer64(r.Get(headerProtocol)), "unsupported Protocol version")
	require(ValidateHeader(c) == nil, "invalid commit root-header")
	require(c.IsRoot(), "invalid commit root-header")
	require(c.Ver() > 0, "invalid commit root-header Ver")
	require(c.PartSize() == r.PartSize(), "invalid commit-header Part-Size")
	require(!c.Created().IsZero(), "invalid commit-header Created")
	require(!c.Updated().IsZero(), "invalid commit-header Updated")
	require(c.Created().Equal(r.Created()) || r.Created().IsZero(), "invalid commit-header Created")
	require(!c.Updated().Before(c.Created()), "invalid commit-header Updated")
	require(VersionIsGreater(c, r), "invalid commit-header Ver")
	require(!c.Deleted(), "invalid commit-header Deleted")
	require(c.PublicKey().Equal(f.pub), "invalid commit-header Public-Key")
	require(c.Verify(), "invalid commit-header Signature")

	//-----------
	curTree := f.nodes
	delFiles := map[string]bool{} // files to delete
	if c.Ver() == r.Ver() {       // if versions are equal than truncate db
		curTree = map[string]*fsNode{}
		for _, nd := range f.nodes {
			if !nd.isDir() && nd.Header.FileSize() > 0 {
				delFiles[nd.path] = true
			}
		}
	}

	//--- verify other headers ---
	updated := make(map[string]Header, len(commit.Headers))
	hh := make([]Header, 0, len(commit.Headers)+len(curTree))
	for _, h := range commit.Headers {
		mustOK(ValidateHeader(h))
		path := h.Path()
		hh = append(hh, h)
		updated[path] = h

		// verify commit-content
		hasMerkle := h.Has(headerMerkleHash)
		if hasMerkle {
			require(len(h.MerkleHash()) == crypto.HashSize, "invalid commit-header")
		}
		switch {
		case h.IsRoot():
			require(hasMerkle, "invalid commit-header")
			require(!h.Deleted(), "invalid commit-header")
			require(h.Has(headerTreeVolume), "invalid commit-header")

		case h.IsFile():
			isZeroLenFile := h.FileSize() == 0 // or is deleted
			require(isZeroLenFile != hasMerkle, "invalid commit-header")
		}
		if h.Deleted() { // delete all sub-files
			require(h.FileSize() == 0, "invalid commit-header")
			curTree[path].walk(func(nd *fsNode) bool {
				if !nd.isDir() && nd.Header.FileSize() > 0 {
					delFiles[nd.path] = true
				}
				return true
			})
		} else { // can`t restore deleted node
			nd := curTree[path]
			require(nd == nil || !nd.Header.Deleted(), "invalid commit-header")
		}
	}
	//--- merge with existed headers ---
	var walk func(*fsNode)
	walk = func(nd *fsNode) {
		if nd == nil {
			return
		}
		h := updated[nd.path]
		if h == nil {
			hh = append(hh, nd.Header)
		}
		if h == nil || !h.Deleted() {
			for _, c := range nd.children {
				walk(c)
			}
		}
	}
	walk(curTree[""])

	//--- update tree
	sortHeaders(hh)
	newTree := mustVal(indexTree(hh))

	//--- verify new root merkle and total-volume (Merkle-Root and Volume headers)
	newRoot := newTree[""]
	newTotalVolume := newRoot.totalVolume()
	require(newTotalVolume == c.GetInt(headerTreeVolume), "invalid commit-header Volume")

	newMerkle := newRoot.childrenMerkleRoot()
	require(bytes.Equal(newMerkle, c.MerkleHash()), "invalid commit-header Merkle-Root")

	rootPartSize := c.PartSize()
	//if rootPartSize == 0 {
	//	rootPartSize = DefaultFilePartSize
	//}

	//--- verify dir`s Merkle-header
	newRoot.walk(func(nd *fsNode) bool {
		if nd.isDir() && !nd.isRoot() {
			require(!nd.Header.Has(headerMerkleHash) ||
				bytes.Equal(nd.Header.MerkleHash(), nd.childrenMerkleRoot()), "invalid commit dir-Merkle")
		}
		return true
	})

	//--- verify and put file content
	mustOK(f.db.Execute(func(tx db.Transaction) (err error) {
		defer recoverError(&err)
		for _, h := range commit.Headers {
			if !h.IsFile() {
				continue
			}
			if hSize, hMerkle := h.FileSize(), h.MerkleHash(); hSize > 0 || len(hMerkle) != 0 {
				partSize := h.PartSize()
				if partSize == 0 {
					partSize = rootPartSize
				}
				require(partSize > 0, "empty commit-header Part-Size")

				r := io.LimitReader(commit.Body, hSize)
				w := crypto.NewMerkleHash(partSize)
				mustOK(tx.Put(h.Path(), io.TeeReader(r, w)))
				require(w.Written() == hSize, "invalid commit-content")
				require(bytes.Equal(w.Root(), h.MerkleHash()), "invalid commit-header Merkle")
				delete(delFiles, h.Path())

				//-------- v0
				//cont := make([]byte, int(hSize))
				//n, err := io.ReadFull(commit.Body, cont)
				//mustOK(err)
				//require(int64(n) == hSize, "invalid commit-content")
				//
				//merkle, _, _ := crypto.ReadMerkleRoot(bytes.NewBuffer(cont), hSize, partSize)
				////require(hSize == sz, "invalid commit-header Size")
				//require(bytes.Equal(h.MerkleHash(), merkle), "invalid commit-header Merkle")
				//
				//err = tx.Put(h.Path(), bytes.NewBuffer(cont))
				//mustOK(err)
				//delete(delFiles, h.Path())

				//-----------
				// TODO: r := crypto.NewMerkleReader(commit.Body, hSize, h.PartSize())
				// tx.Put(key, r) // put reader
				// require(bytes.Equal(h.Merkle(), r.MerkleRoot()))
				// require(r.ReadSize() == size, "invalid commit-header Size")

				// todo: put content by hash (put if not exists, delete on error)
				//key:=fmt.Sprintf("X%x", merkle[:16])
				//exst, err:= f.db.Exists(key)
				//mustOK(err)
				//if !exst {
				//	err = f.db.Put(key, bytes.NewBuffer(cont))
				//	mustOK(err)
				//}
			}
		}

		//--- delete old files (???) -----
		for path := range delFiles {
			mustOK(tx.Delete(path))
		}
		//--- save to Storage
		mustOK(db.PutJSON(tx, dbKeyHeaders, hh))
		return
	}))

	f.nodes = newTree
	return
}
