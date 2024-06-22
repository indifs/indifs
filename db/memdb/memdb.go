package memdb

import (
	"bytes"
	"fmt"
	"github.com/indifs/indifs/db"
	"io"
	"sync"
)

type memDB map[string][]byte

type memTx memDB

type memValue struct { // implements io.ReadSeekCloser
	*bytes.Reader
}

func (v memValue) Close() error {
	return nil
}

func (s memDB) Get(key string) ([]byte, error) {
	return s[key], nil
}

func (s memDB) Open(key string) (io.ReadSeekCloser, error) {
	return memValue{bytes.NewReader(s[key])}, nil
}

var memDBMx sync.Mutex

func (s memDB) Execute(fn func(db.Transaction) error) (err error) {
	defer recoverErr(&err)
	memDBMx.Lock()
	defer memDBMx.Unlock()
	return fn(memTx(s))
}

func (s memTx) Put(key string, value io.Reader) (err error) {
	s[key], err = io.ReadAll(value)
	return
}

func (s memTx) Delete(key string) error {
	delete(s, key)
	return nil
}

func New() db.Storage {
	return &memDB{}
}

func recoverErr(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("%v", r)
	}
}
