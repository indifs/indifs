package ifs

import (
	"bytes"
	"github.com/indifs/indifs/crypto"
	"io"
	"io/fs"
	"sort"
	"strings"
	"time"
)

type Commit struct {
	Headers []Header
	Body    io.ReadCloser
}

func (c *Commit) Root() Header {
	return c.Headers[0]
}

func (c *Commit) Ver() int64 {
	return c.Root().Ver()
}

func (c *Commit) Updated() time.Time {
	return c.Root().Updated()
}

func (c *Commit) Hash() []byte {
	return c.Root().Hash()
}

func (c *Commit) BodySize() (n int64) {
	for _, h := range c.Headers {
		n += h.FileSize()
	}
	return
}

func (c *Commit) Trace() {
	traceHeaders(c.Headers)
}

func MakeCommit(vfs IFS, prv crypto.PrivateKey, src fs.FS, ts time.Time) (commit *Commit, err error) {
	defer catch(&err)

	root := tryVal(vfs.FileHeader("/"))
	ver := root.Ver() + 1       // new ver
	partSize := root.PartSize() //

	files := newFilesReader()
	commit = &Commit{Body: files}

	inBatch := map[string]bool{}
	onDisk := map[string]bool{}

	var hh []Header
	var diskWalk func(string)
	diskWalk = func(path string) {
		if !IsValidPath(path) {
			return
		}
		var dfsPath = path[1:] // trim prefix '/'
		var isDir = strings.HasSuffix(path, "/")
		h, err := vfs.FileHeader(path)
		if err == ErrNotFound {
			err = nil
		}
		try(err)
		exists := h != nil
		if h == nil {
			h = Header{{headerPath, []byte(path)}}
		}
		onDisk[path] = true
		var fileMerkle []byte
		var fileSize int64
		if !isDir {
			fileSize, fileMerkle, _ = fsMerkleRoot(src, dfsPath, partSize)
		}
		if path == "/" || !exists || !isDir && !bytes.Equal(h.GetBytes(headerFileMerkle), fileMerkle) { // not exists or changed
			h.SetInt(headerVer, ver) // set new version
			if !isDir {
				h.SetInt(headerFileSize, fileSize)
				h.SetBytes(headerFileMerkle, fileMerkle)
				files.add(func() (io.ReadCloser, error) {
					return src.Open(dfsPath)
				})
			}
			commit.Headers = append(commit.Headers, h)
			inBatch[path], hh = true, append(hh, h)
		}
		if isDir { //- read dir
			if dfsPath == "" {
				dfsPath = "."
			}
			dfsPath = strings.TrimSuffix(dfsPath, "/")
			dd := tryVal(fs.ReadDir(src, dfsPath))
			if len(dd) > MaxPathDirFilesCount {
				try(ErrTooManyFiles)
			}
			sort.Slice(dd, func(i, j int) bool { // sort
				return pathLess(dd[i].Name(), dd[j].Name())
			})
			for _, f := range dd {
				if !isValidPathName(f.Name()) {
					continue
				}
				if f.IsDir() {
					diskWalk(path + f.Name() + "/")
				} else {
					diskWalk(path + f.Name())
				}
			}
		}
	}
	diskWalk("/")

	//-- add old headers to commit
	var vfsWalk func(Header)
	vfsWalk = func(h Header) {
		path := h.Path()
		if !onDisk[path] { // delete node
			h = Header{{headerPath, []byte(path)}}
			h.SetInt(headerVer, ver)
			h.SetInt(headerDeleted, 1)
			hh = append(hh, h)
			commit.Headers = append(commit.Headers, h)
			return // skip all child nodes
		}
		if !inBatch[path] {
			hh = append(hh, h)
		}
		ff, err := vfs.ReadDir(path)
		if err == ErrNotFound {
			err = nil
		}
		try(err)
		for _, h := range ff {
			vfsWalk(h)
		}
	}
	vfsWalk(root)

	//-- calc new commit merkle
	sortHeaders(commit.Headers)
	sortHeaders(hh)
	newTree := tryVal(indexTree(hh))
	ndRoot := newTree["/"]

	//--- set merkle + sign
	newRoot := &commit.Headers[0]
	if !newRoot.Has(headerCreated) {
		newRoot.SetTime(headerCreated, ts)
	}
	newRoot.SetTime(headerUpdated, ts)
	newRoot.SetInt(headerTreeVolume, ndRoot.totalVolume())
	newRoot.SetBytes(headerTreeMerkle, ndRoot.childrenMerkleRoot())
	newRoot.Sign(prv)
	return
}

func fsMerkleRoot(dfs fs.FS, path string, partSize int64) (size int64, merkle []byte, hashes [][]byte) {
	f := tryVal(dfs.Open(path))
	defer f.Close()
	w := crypto.NewMerkleHash(partSize)
	tryVal(io.Copy(w, f))
	return w.Written(), w.Root(), w.Leaves()
}
