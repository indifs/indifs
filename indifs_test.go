package indifs

import (
	"bytes"
	"github.com/indifs/indifs/crypto"
	"github.com/indifs/indifs/database/memdb"
	"github.com/indifs/indifs/test_data"
	"io"
	"testing"
	"time"
)

func Test_protocolVer64(t *testing.T) {
	assert(t, protocolVer64("IndiFS/0.1") == 0x0000000100000000)
	assert(t, protocolVer64("UNKNOWN/0.1") == 0xffffffffffffffff)
}

func Test_protocolVerMajor(t *testing.T) {
	assert(t, protocolVerMajor("IndiFS/0.1") == 0)
	assert(t, protocolVerMajor("IndiFS/1") == 1)
	assert(t, protocolVerMajor("UnknownPrefixFS/0.1") == 255)
}

func TestMakeCommit(t *testing.T) {

	s := newTestIFS()

	//---------- commit-1 (init data)
	commit1 := makeTestCommit(s, "commit1")
	assert(t, len(commit1.Headers) > 1)
	assert(t, commit1.Headers[0].IsRoot())
	assert(t, commit1.Headers[1].Path() == "/")
	assert(t, commit1.Ver() == 1)
	assert(t, commit1.Headers[1].Ver() == 1)
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
	trace("====== commit1A", commit1A)

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
	h.SetBytes("Merkle", append(h.MerkleHash(), 0)) // modify commit: modify header Merkle for last line (readme.txt)
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
	commitA := makeTestCommit(newTestIFS(), "commit1")
	commitB := makeTestCommit(newTestIFS(), "commit1")
	commitB.Headers[0].Add("X", "x")
	commitB.Headers[0].Sign(testPrv)
	if bytes.Compare(commitA.Hash(), commitB.Hash()) > 0 {
		commitA, commitB = commitB, commitA
	}
	assert(t, commitA.Ver() == commitB.Ver())
	assert(t, commitA.Updated().Equal(commitB.Updated()))
	assert(t, bytes.Compare(commitA.Hash(), commitB.Hash()) < 0)

	//----- apply commit
	s := newTestIFS()
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

	s3 := applyCommit(newTestIFS(), "commit1", "commit2", "commit3")

	//--------
	s1 := applyCommit(newTestIFS(), "commit1")
	r1 := s1.Root()

	// request commit from current version
	commit1, err := s3.GetCommit(r1.Ver())
	assert(t, err == nil)
	assert(t, len(commit1.Headers) > 1)
	assert(t, commit1.Root().Ver() == 3)

	err = s1.Commit(commit1)
	assert(t, err == nil)
	assert(t, equal(fsHeaders(s3), fsHeaders(s1)))

	//--------
	s2 := applyCommit(newTestIFS(), "commit1")

	// request full commit (from 0version)
	commit2, err := s3.GetCommit(0)
	assert(t, err == nil)
	assert(t, len(commit2.Headers) > 1)
	assert(t, commit2.Root().Ver() == 3)

	err = s2.Commit(commit2)
	assert(t, err == nil)
	assert(t, equal(fsHeaders(s3), fsHeaders(s2)))

}

func TestFileSystem_FileMerkleProof(t *testing.T) {
	s := applyCommit(newTestIFS(), "commit1", "commit2")
	merkleRoot := s.Root().MerkleHash()

	// make merkle proof for each file
	for _, h := range fsHeaders(s)[1:] {
		merkleProof, err := s.FileMerkleProof(h.Path())
		assert(t, err == nil)
		assert(t, len(merkleProof)%33 == 0)

		ok := h.VerifyMerkleProof(merkleRoot, merkleProof)
		assert(t, ok)

		if h.IsFile() {
			parts, err := s.FileParts(h.Path())
			assert(t, err == nil)
			assert(t, bytes.Equal(h.MerkleHash(), crypto.MerkleRoot(parts...)))
		}
	}
}

func makeTestCommit(vfs IFS, commitID string) *Commit {
	tCommit := vfs.Root().Updated()
	if tCommit.IsZero() {
		tCommit = mustVal(time.Parse("2006-01-02 15:04:05", "2024-11-05 00:00:00"))
	} else {
		tCommit = tCommit.Add(time.Second)
	}
	return mustVal(MakeCommit(vfs, testPrv, test_data.FS(commitID), tCommit))
}

func fsHeaders(f IFS) (hh []Header) {
	return f.(*fileSystem).headers()
}

func applyCommit(f IFS, commitName ...string) IFS {
	for _, name := range commitName {
		must(f.Commit(makeTestCommit(f, name)))
	}
	return f
}

func newTestIFS() IFS {
	return mustVal(OpenFS(testPub, memdb.New()))
}
