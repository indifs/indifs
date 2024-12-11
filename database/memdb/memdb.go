package memdb

import (
	"bytes"
	"fmt"
	"github.com/indifs/indifs/database"
	"io"
	"sync"
)

// memDB implements database.Storage
type memDB struct {
	mx   sync.RWMutex
	tabs map[string]*memTab
}

type memTab struct {
	mx   sync.RWMutex
	data map[string][]byte
}

// memTx implements db.Transaction
type memTx map[string][]byte

func New() database.Storage {
	return &memDB{tabs: map[string]*memTab{}}
}

func (s *memDB) Drop(table string) (err error) {
	s.mx.Lock()
	defer s.mx.Unlock()
	delete(s.tabs, table)
	return
}

func (s *memDB) rTab(table string) *memTab {
	s.mx.RLock()
	defer s.mx.RUnlock()
	return s.tabs[table]
}

func (s *memDB) tab(table string) (t *memTab) {
	if t = s.rTab(table); t != nil {
		return
	}
	s.mx.Lock()
	defer s.mx.Unlock()
	if t = s.tabs[table]; t == nil {
		t = &memTab{data: map[string][]byte{}}
		s.tabs[table] = t
	}
	return
}

func (s *memDB) OpenAt(table, key string, offset int64) (r io.ReadCloser, err error) {
	tab := s.rTab(table)
	if tab == nil {
		return nil, database.ErrNotFound
	}
	tab.mx.RLock()
	defer tab.mx.RUnlock()
	data, ok := tab.data[key]
	if !ok || offset > int64(len(data)) {
		return nil, database.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(data[offset:])), nil
}

func (s *memDB) Execute(table string, fn func(database.Transaction) error) (err error) {
	tab := s.tab(table)

	tab.mx.Lock()
	defer tab.mx.Unlock()

	tx := memTx{}
	err = func() (err error) {
		defer recoverError(&err)
		return fn(tx)
	}()
	if err != nil {
		return err
	}
	for key, val := range tx { // merge tx-data
		if val != nil {
			tab.data[key] = val
		} else {
			delete(tab.data, key)
		}
	}
	return nil
}

func (tx memTx) Put(key string, n int64, r io.Reader) (err error) {
	tx[key], err = io.ReadAll(io.LimitReader(r, n))
	return
}

func (tx memTx) Delete(key string) error {
	tx[key] = nil
	return nil
}

func recoverError(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("%v", r)
	}
}
