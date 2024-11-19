package memdb

import (
	"bytes"
	"fmt"
	"github.com/indifs/indifs/db"
	"io"
	"sync"
)

// memDB implements db.Storage
type memDB struct {
	mx   sync.RWMutex
	data map[string][]byte
}

// memTx implements db.Transaction
type memTx struct {
	db *memDB
}

func New() db.Storage {
	return &memDB{data: map[string][]byte{}}
}

func (s *memDB) Get(key string) ([]byte, error) {
	s.mx.RLock()
	defer s.mx.RUnlock()
	return s.data[key], nil
}

func (s *memDB) Open(key string) (io.ReadSeekCloser, error) {
	s.mx.RLock()
	defer s.mx.RUnlock()
	return readSeekCloser{bytes.NewReader(s.data[key])}, nil
}

func (s *memDB) Execute(fn func(db.Transaction) error) (err error) {
	defer catch(&err)
	s.mx.Lock()
	defer s.mx.Unlock()
	return fn(memTx{s})
}

func (tx memTx) Put(key string, value io.Reader) (err error) {
	tx.db.data[key], err = io.ReadAll(value)
	return
}

func (tx memTx) Delete(key string) error {
	delete(tx.db.data, key)
	return nil
}

// readSeekCloser implements io.ReadSeekCloser
type readSeekCloser struct {
	*bytes.Reader
}

func (v readSeekCloser) Close() error {
	return nil
}

func catch(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("%v", r)
	}
}
