package indifs

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
	Info    Header
	Headers []Header
	Body    io.ReadCloser
}

func (c *Commit) Root() Header {
	return c.Headers[0]
}

func (c *Commit) Author() crypto.PublicKey {
	return c.Root().PublicKey()
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

func (c *Commit) String() string {
	buf := bytes.NewBuffer(nil)
	for _, h := range c.Headers {
		buf.WriteString(h.String())
		buf.WriteString("\n")
	}
	return buf.String()
}

func (c *Commit) Trace() {
	traceHeaders(c.Headers)
}

func MakeCommit(ifs IFS, prv crypto.PrivateKey, src fs.FS, ts time.Time) (commit *Commit, err error) {
	defer recoverError(&err)

	root := ifs.Root().Copy()   // root info
	ver := root.Ver() + 1       // new ver
	partSize := root.PartSize() //

	if ts.IsZero() {
		ts = time.Now()
	}
	if ts.Unix() <= root.Updated().Unix() {
		ts = root.Updated().Add(time.Second)
	}

	files := newMultiReader()
	commit = &Commit{
		Headers: []Header{root},
		Body:    files,
	}
	commit.Info.SetInt("PrevVer", root.Ver())
	//commit.Info.SetBytes("PrevHash", root.Hash())

	mCommit := map[string]bool{"": true}          //
	mDisk := map[string]bool{"": true, "/": true} // on disk

	var newHH = []Header{root} // new fs headers
	var diskWalk func(string)
	diskWalk = func(path string) {
		if !IsValidPath(path) {
			return
		}
		var dfsPath = path[1:] // trim prefix '/'
		var isDir = strings.HasSuffix(path, "/")
		h := valExcludedNotFound(ifs.FileHeader(path))
		exists := h != nil
		if !exists {
			h = NewHeader(path)
		}
		mDisk[path] = true
		var fileMerkle []byte
		var fileSize int64
		if !isDir {
			fileSize, fileMerkle, _ = fsMerkleRoot(src, dfsPath, partSize)
		}
		if !exists || !isDir && !bytes.Equal(h.GetBytes(headerMerkleHash), fileMerkle) { // not exists or changed
			h.SetInt(headerVer, ver) // set new version
			if !isDir {
				h.SetInt(headerFileSize, fileSize)
				h.SetBytes(headerMerkleHash, fileMerkle)
				files.add(func() (io.ReadCloser, error) {
					return src.Open(dfsPath)
				})
			}
			commit.Headers = append(commit.Headers, h)
			mCommit[path], newHH = true, append(newHH, h)
		}
		if isDir { //- read dir
			if dfsPath == "" {
				dfsPath = "."
			}
			dfsPath = strings.TrimSuffix(dfsPath, "/")
			dd := mustVal(fs.ReadDir(src, dfsPath))
			dd = sliceFilter(dd, func(f fs.DirEntry) bool { // exclude invalid names
				return isValidPathName(f.Name())
			})
			require(len(dd) <= MaxPathDirFilesCount, ErrTooManyFiles)
			sort.Slice(dd, func(i, j int) bool { // sort
				return pathLess(dd[i].Name(), dd[j].Name())
			})
			for _, f := range dd {
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
		if !mDisk[path] { // delete node
			h = NewHeader(path)
			h.SetInt(headerVer, ver)
			h.SetInt(headerDeleted, 1)
			newHH = append(newHH, h)
			commit.Headers = append(commit.Headers, h)
			return // skip all child nodes
		}
		if !mCommit[path] {
			newHH = append(newHH, h)
		}
		ff := valExcludedNotFound(ifs.ReadDir(path))
		for _, h := range ff {
			vfsWalk(h)
		}
	}
	vfsWalk(root)

	//-- calc new commit merkle
	sortHeaders(commit.Headers)
	sortHeaders(newHH)
	newTree := mustVal(indexTree(newHH))
	ndRoot := newTree[""]

	//--- set merkle + sign
	newRoot := &commit.Headers[0]
	if !newRoot.Has(headerCreated) {
		newRoot.SetTime(headerCreated, ts)
	}
	newRoot.SetTime(headerUpdated, ts)
	newRoot.SetInt(headerVer, ver)
	newRoot.SetInt(headerTreeVolume, ndRoot.totalVolume())
	newRoot.SetBytes(headerMerkleHash, ndRoot.childrenMerkleRoot())
	newRoot.Sign(prv)
	return
}

func fsMerkleRoot(dfs fs.FS, path string, partSize int64) (size int64, merkle []byte, hashes [][]byte) {
	f := mustVal(dfs.Open(path))
	defer f.Close()
	w := crypto.NewMerkleHash(partSize)
	mustVal(io.Copy(w, f))
	return w.Written(), w.Root(), w.Leaves()
}
