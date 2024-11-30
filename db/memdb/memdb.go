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
type memTx map[string][]byte

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

func (s *memDB) Execute(fn func(db.Transaction) error) error {
	s.mx.Lock()
	defer s.mx.Unlock()

	tx := memTx{}
	err := func() (err error) {
		defer catch(&err)
		return fn(tx)
	}()
	if err != nil {
		return err
	}
	for key, val := range tx { // merge tx-data
		if val != nil {
			s.data[key] = val
		} else {
			delete(s.data, key)
		}
	}
	return nil
}

func (tx memTx) Put(key string, r io.Reader) (err error) {
	tx[key], err = io.ReadAll(r)
	return
}

func (tx memTx) Delete(key string) error {
	tx[key] = nil
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
