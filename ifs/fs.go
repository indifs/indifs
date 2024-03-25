package ifs

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
	defer catch(&err)
	s := &fileSystem{
		pub: pub,
		db:  db,
	}
	s.initDB()
	return s, nil
}

func (f *fileSystem) setPartSize(size int64) {
	f.nodes["/"].Header.SetInt(headerFilePartSize, size)
}

//func (f *fileSystem) PublicKey() crypto.PublicKey {
//	return f.pub
//}

func (f *fileSystem) headers() (hh []Header) {
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
	try(db.GetJSON(f.db, dbKeyHeaders, &hh))
	if hh == nil { // empty db
		hh = []Header{NewRootHeader(f.pub)}
	}
	f.nodes = tryVal(indexTree(hh))
}

func (f *fileSystem) fileHeader(path string) Header {
	if nd := f.nodes[path]; nd != nil {
		return nd.Header
	}
	return nil
}

func (f *fileSystem) root() Header {
	return f.nodes["/"].Header
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
	witness = f.nodes["/"].childrenMerkleWitness(path)
	return witness[:crypto.HashSize], witness[crypto.HashSize:], nil
}

func (f *fileSystem) rootPartSize() int64 {
	if size := f.root().PartSize(); size > 0 {
		return size
	}
	return DefaultFilePartSize
}

func (f *fileSystem) FileParts(path string) (hashes [][]byte, err error) {
	f.mx.RLock()
	defer f.mx.RUnlock()

	h := f.fileHeader(path)
	if h == nil {
		err = ErrNotFound
		return
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
	_, err = io.Copy(w, fl)
	hashes = w.Leaves()
	return
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
	defer catch(&err)

	root := f.nodes["/"]
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
	f.mx.Lock()
	defer f.mx.Unlock()
	defer catch(&err)

	//--- verify commit ---
	require(len(commit.Headers) > 0, "empty commit")
	sortHeaders(commit.Headers)

	//--- verify root-header ---
	r := f.root()
	b := commit.Root()

	require(b.Get(headerProtocol) == DefaultProtocol, "unsupported Protocol")
	try(ValidateHeader(b))
	require(b.Path() == "/", "invalid commit-header Path")
	require(b.Ver() > 0, "invalid commit-header Ver")
	require(b.PartSize() == r.PartSize(), "invalid commit-header Part-Size")
	require(!b.Created().IsZero(), "invalid commit-header Created")
	require(!b.Updated().IsZero(), "invalid commit-header Updated")
	require(b.Created().Equal(r.Created()) || r.Created().IsZero(), "invalid commit-header Created")
	require(!b.Updated().Before(b.Created()), "invalid commit-header Updated")
	require(VersionIsGreater(b, r), "invalid commit-header Ver")
	require(!b.Deleted(), "invalid commit-header Deleted")
	require(b.PublicKey().Equal(f.pub), "invalid commit-header Public-Key")
	require(b.Verify(), "invalid commit-header Signature")

	//-----------
	curTree := f.nodes
	delFiles := map[string]bool{} // files to delete
	if b.Ver() == r.Ver() {       // if versions are equal than truncate db
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
		try(ValidateHeader(h))
		path := h.Path()
		hh = append(hh, h)
		updated[path] = h

		// verify commit-content
		if h.IsDir() || h.Deleted() { // dir or deleted file
			require(!h.Has(headerFileMerkle), "invalid commit-header")
			require(!h.Has(headerFileSize), "invalid commit-header")
		} else { // is not deleted file
			require(h.FileSize() == 0 && !h.Has(headerFileMerkle) || h.FileSize() > 0 && len(h.FileMerkle()) == crypto.HashSize, "invalid commit-header")
		}
		if h.Deleted() { // delete all sub-files
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
	walk(curTree["/"])

	//--- update tree
	sortHeaders(hh)
	newTree := tryVal(indexTree(hh))

	//--- verify new root merkle and total-volume (Merkle-Root and Volume headers)
	newMerkle := newTree["/"].childrenMerkleRoot()
	totalVolume := newTree["/"].totalVolume()
	require(totalVolume == b.GetInt(headerTreeVolume), "invalid commit-header Volume")
	require(bytes.Equal(newMerkle, b.TreeMerkleRoot()), "invalid commit-header Merkle-Root")

	rootPartSize := b.PartSize()
	//if rootPartSize == 0 {
	//	rootPartSize = DefaultFilePartSize
	//}

	//--- verify and put file content
	try(f.db.Execute(func(tx db.Transaction) (err error) {
		defer catch(&err)
		for _, h := range commit.Headers {
			if hSize, hMerkle := h.FileSize(), h.FileMerkle(); hSize > 0 || len(hMerkle) != 0 {
				partSize := h.PartSize()
				if partSize == 0 {
					partSize = rootPartSize
				}
				require(partSize > 0, "empty commit-header Part-Size")

				r := io.LimitReader(commit.Body, hSize)
				w := crypto.NewMerkleHash(partSize)
				try(tx.Put(h.Path(), io.TeeReader(r, w)))
				require(w.Written() == hSize, "invalid commit-content")
				require(bytes.Equal(w.Root(), h.FileMerkle()), "invalid commit-header Merkle")
				delete(delFiles, h.Path())

				//-------- v0
				//cont := make([]byte, int(hSize))
				//n, err := io.ReadFull(commit.Body, cont)
				//try(err)
				//require(int64(n) == hSize, "invalid commit-content")
				//
				//merkle, _, _ := crypto.ReadMerkleRoot(bytes.NewBuffer(cont), hSize, partSize)
				////require(hSize == sz, "invalid commit-header Size")
				//require(bytes.Equal(h.FileMerkle(), merkle), "invalid commit-header Merkle")
				//
				//err = tx.Put(h.Path(), bytes.NewBuffer(cont))
				//try(err)
				//delete(delFiles, h.Path())

				//-----------
				// TODO: r := crypto.NewMerkleReader(commit.Body, hSize, h.PartSize())
				// tx.Put(key, r) // put reader
				// require(bytes.Equal(h.Merkle(), r.MerkleRoot()))
				// require(r.ReadSize() == size, "invalid commit-header Size")

				// todo: put content by hash (put if not exists, delete on error)
				//key:=fmt.Sprintf("X%x", merkle[:16])
				//exst, err:= f.db.Exists(key)
				//try(err)
				//if !exst {
				//	err = f.db.Put(key, bytes.NewBuffer(cont))
				//	try(err)
				//}
			}
		}

		//--- delete old files (???) -----
		for path := range delFiles {
			try(tx.Delete(path))
		}
		//--- save to Storage
		try(db.PutJSON(tx, dbKeyHeaders, hh))
		return
	}))

	f.nodes = newTree
	return
}
