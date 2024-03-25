package ifs

import (
	"bytes"
	"errors"
	"io"
	"strings"
)

// IFS is Virtual File System
type IFS interface {

	// FileHeader returns Header of file or directory
	FileHeader(path string) (Header, error)

	// FileMerkleWitness returns hash and merkle-witness for file or dir-header
	FileMerkleWitness(path string) (hash, witness []byte, err error)

	// FileParts returns hashes of file-parts
	FileParts(path string) (hashes [][]byte, err error)

	// OpenAt opens file as descriptor
	OpenAt(path string, offset int64) (io.ReadCloser, error)

	// ReadDir returns headers of directory files
	ReadDir(path string) ([]Header, error)

	// GetCommit makes commit starting from the given version
	GetCommit(ver int64) (*Commit, error)

	Get(request string) (*Commit, error)

	// Commit applies a commit
	Commit(*Commit) error
}

const (
	DefaultProtocol     = "0.1"
	DefaultFilePartSize = 1 << 20 // (1 MiB) – default file part size

	MaxPathNameLength    = 255
	MaxPathLevels        = 6
	MaxPathDirFilesCount = 4096

	//MaxPathLength = MaxPathNameLength * MaxPathLevels
	//pathNameChars = ".-_~@0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrTooManyFiles = errors.New("too many files")

	errInvalidHeader = errors.New("invalid header")
	errInvalidPath   = errors.New("invalid header Path")
)

var (
	errSeveralNodes       = errors.New("several nodes with the same path")
	errParentDirNotFound  = errors.New("parent dir not found")
	errParentDirIsDeleted = errors.New("parent dir is deleted")
)

// IsValidPath says the path is valid
func IsValidPath(path string) bool {
	if path == "/" {
		return true
	}
	n := len(path)
	if n == 0 || path[0] != '/' {
		return false
	}
	//path = path[1:] // trim prefix '/'
	for i, name := range splitPath(path) {
		if i >= MaxPathLevels || !isValidPathName(name) {
			return false
		}
	}
	return true
}

func isValidPathName(part string) bool {
	return part != "" &&
		part != "." &&
		len(part) <= MaxPathNameLength &&
		!strings.HasPrefix(part, "..") &&
		!strings.ContainsAny(part, "/\x00") &&
		strings.TrimSpace(part) != ""
}

func splitPath(path string) (parts []string) {
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/") // for directory
	var part strings.Builder
	esc := false
	for _, r := range path {
		switch {
		case esc:
			part.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == '/':
			parts = append(parts, part.String())
			part.Reset()
		default:
			part.WriteRune(r)
		}
	}
	if part.Len() > 0 {
		parts = append(parts, part.String())
	}
	return
}

func pathLess(a, b string) bool {
	A := splitPath(a)
	B := splitPath(b)
	nB := len(B)
	for i, Ai := range A {
		if nB < i+1 {
			return false
		} else if Ai != B[i] {
			return Ai < B[i]
		}
	}
	return true
}

func dirname(path string) string {
	if n := len(path); n > 0 {
		if path[n-1] == '/' { // is dir
			path = path[:n-1]
		}
		if i := strings.LastIndexByte(path, '/'); i >= 0 {
			return path[:i+1]
		}
	}
	return ""
}

// VersionIsGreater checks that the version of header A is higher than the version of header B
func VersionIsGreater(a, b Header) bool {
	if a.Ver() != b.Ver() {
		return a.Ver() > b.Ver()
	}
	//if t1, t2 := a.Updated(), b.Updated(); t1 != t2 {
	//	return t1.Before(t2)
	//}
	return bytes.Compare(a.Hash(), b.Hash()) > 0
}
