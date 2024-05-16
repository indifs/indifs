package ifs

import (
	"bytes"
	"github.com/indifs/indifs/crypto"
	"github.com/indifs/indifs/db"
	"github.com/indifs/indifs/db/memdb"
	"github.com/indifs/indifs/ifs/test_data"
	"io"
	"testing"
	"time"
)

func TestMakeCommit(t *testing.T) {

	s := newMemIFS()

	//---------- commit-1 (init data)
	commit1 := makeTestCommit(s, "commit1")
	assert(t, len(commit1.Headers) > 1)
	assert(t, commit1.Ver() == 1)
	trace("====== commit1", commit1)

	// apply commit
	err := s.Commit(commit1)
	assert(t, err == nil)
	trace("====== db-1", s)

	// reapply the same commit - FAIL
	err = s.Commit(commit1)
	assert(t, err != nil)

	//------ repeat commit-1 (the same files; changed root-header only)
	commit1A := makeTestCommit(s, "commit1")
	assert(t, len(commit1A.Headers) == 1)
	assert(t, commit1A.Ver() == 2)

	err = s.Commit(commit1A)
	assert(t, err == nil)
	trace("====== db-1a", s)

	//------- commit-2
	commit2 := makeTestCommit(s, "commit2")
	trace("====== commit2", commit2)
	assert(t, len(commit2.Headers) > 1)
	assert(t, commit2.Ver() == 3)

	err = s.Commit(commit2)
	assert(t, err == nil)
	trace("====== db-2", s)

	//------ make invalid commit
	invalidCommit := makeTestCommit(s, "commit3")
	invalidCommit.Headers[0].Set("Updated", "2020-01-03T00:00:01Z") // modify commit data
	trace("====== invalid commit-1", invalidCommit)
	err = s.Commit(invalidCommit)
	assert(t, err != nil)

	//------ make invalid commit-2
	invalidCommit = makeTestCommit(s, "commit3")
	h := &invalidCommit.Headers[len(invalidCommit.Headers)-1]
	h.SetInt("Size", h.FileSize()+1) // modify commit-line-header Size for readme.txt file
	trace("====== invalid commit-2", invalidCommit)
	err = s.Commit(invalidCommit)
	assert(t, err != nil)

	//------ make invalid commit-3
	invalidCommit = makeTestCommit(s, "commit3")
	h = &invalidCommit.Headers[len(invalidCommit.Headers)-1]
	h.SetBytes("Merkle", append(h.FileMerkle(), 0)) // modify commit: modify header Merkle for last line (readme.txt)
	trace("====== invalid commit-3", invalidCommit)
	err = s.Commit(invalidCommit)
	assert(t, err != nil)

	//------ make invalid commit-4
	invalidCommit = makeTestCommit(s, "commit3")
	cont, _ := io.ReadAll(invalidCommit.Body)
	cont[len(cont)-1]++
	invalidCommit.Body = io.NopCloser(bytes.NewBuffer(cont)) // modify Content
	trace("====== invalid commit-4", invalidCommit)
	err = s.Commit(invalidCommit)
	assert(t, err != nil)

	//------ make invalid commit-5
	invalidCommit = makeTestCommit(s, "commit3")
	invalidCommit.Headers = invalidCommit.Headers[:len(invalidCommit.Headers)-1] // modify commit: delete last header
	trace("====== invalid commit-5", invalidCommit)
	err = s.Commit(invalidCommit)
	assert(t, err != nil)

	//------- commit-3
	commit3 := makeTestCommit(s, "commit3")
	trace("====== commit3", commit3)
	assert(t, len(commit3.Headers) > 1)
	assert(t, commit3.Ver() == 4)

	err = s.Commit(commit3)
	assert(t, err == nil)
	trace("====== db-3", s)

	//------- check result
	B, err := s.FileHeader("/B/")
	assert(t, err == nil)
	assert(t, B != nil)
	assert(t, B.Deleted())

	B2, err := s.FileHeader("/B/2/")
	assert(t, err != nil)
	assert(t, B2 == nil)
}

func TestFileSystem_Commit_conflictCommits(t *testing.T) {

	//----- make two conflict commits. A.Ver == B.Ver && A.Updated == B.Updated
	commitA := makeTestCommit(newMemIFS(), "commit1")
	commitB := makeTestCommit(newMemIFS(), "commit1")
	commitB.Headers[0].Add("X", "x")
	commitB.Headers[0].Sign(testPrv)
	if bytes.Compare(commitA.Hash(), commitB.Hash()) > 0 {
		commitA, commitB = commitB, commitA
	}
	assert(t, commitA.Ver() == commitB.Ver())
	assert(t, commitA.Updated().Equal(commitB.Updated()))
	assert(t, bytes.Compare(commitA.Hash(), commitB.Hash()) < 0)

	//----- apply commit
	s := newMemIFS()
	err := s.Commit(commitA)
	assert(t, err == nil)

	//----- apply alternative commit with great version. OK
	err = s.Commit(commitB)
	assert(t, err == nil)

	//----- apply alternative commit with low version. FAIL
	err = s.Commit(commitA)
	assert(t, err != nil)
}

func TestFileSystem_GetCommit(t *testing.T) {

	s3 := applyCommit(newMemIFS(), "commit1", "commit2", "commit3")

	//--------
	s1 := applyCommit(newMemIFS(), "commit1")
	r1, err := s1.FileHeader("/")
	assert(t, err == nil)

	// request commit from current version
	commit1, err := s3.GetCommit(r1.Ver())
	assert(t, err == nil)
	assert(t, len(commit1.Headers) > 1)
	assert(t, commit1.Root().Ver() == 3)

	err = s1.Commit(commit1)
	assert(t, err == nil)
	assert(t, toJSON(fsHeaders(s3)) == toJSON(fsHeaders(s1)))

	//--------
	s2 := applyCommit(newMemIFS(), "commit1")

	// request full commit (from 0version)
	commit2, err := s3.GetCommit(0)
	assert(t, err == nil)
	assert(t, len(commit2.Headers) > 1)
	assert(t, commit2.Root().Ver() == 3)

	err = s2.Commit(commit2)
	assert(t, err == nil)
	assert(t, toJSON(fsHeaders(s3)) == toJSON(fsHeaders(s2)))

}

func TestFileSystem_FileMerkleWitness(t *testing.T) {
	s := applyCommit(newMemIFS(), "commit1")
	hh := fsHeaders(s)
	merkleRoot := hh[0].TreeMerkleRoot()

	for _, h := range hh[1:] {
		// make merkle witness for each file
		fileHash, fileWitness, err := s.FileMerkleWitness(h.Path())
		assert(t, err == nil)
		assert(t, bytes.Equal(fileHash, h.Hash()))
		assert(t, len(fileWitness) > 0 && len(fileWitness)%33 == 0)
		assert(t, len(fileHash) == 32)

		// verify merkle-witness
		ok := crypto.VerifyMerkleWitness(fileHash, merkleRoot, fileWitness)
		assert(t, ok)

		if h.IsFile() {
			parts, err := s.FileParts(h.Path())
			assert(t, err == nil)
			assert(t, bytes.Equal(h.FileMerkle(), crypto.MerkleRoot(parts...)))
		}
	}
}

func makeTestCommit(vfs IFS, commitName string) *Commit {
	hRoot := tryVal(vfs.FileHeader("/"))
	tCommit := hRoot.Updated().Add(time.Second)
	return tryVal(MakeCommit(vfs, testPrv, test_data.FS(commitName), tCommit))
}

func fsHeaders(f IFS) (hh []Header) {
	return f.(*fileSystem).headers()
}

func newMemIFS() IFS {
	var t0 = tryVal(time.Parse("2006-01-02 15:04:05", "2024-11-05 00:00:00"))

	d := memdb.New()
	try(d.Execute(func(tx db.Transaction) error { // init DB
		h0 := NewRootHeader(testPub)
		h0.SetTime("Created", t0)
		h0.SetTime("Updated", t0)
		h0.SetInt(headerFilePartSize, 1024)
		return db.PutJSON(tx, dbKeyHeaders, []Header{h0})
	}))
	return tryVal(OpenFS(testPub, d))
}

func applyCommit(f IFS, commitName ...string) IFS {
	for _, name := range commitName {
		try(f.Commit(makeTestCommit(f, name)))
	}
	return f
}
