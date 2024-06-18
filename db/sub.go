package db

import "io"

func Sub(db Storage, prefix string) Storage {
	return &subStorage{prefix, db}
}

type subStorage struct {
	prefix string
	db     Storage
}

type subTransaction struct {
	prefix string
	tx     Transaction
}

func (d *subStorage) Open(key string) (io.ReadSeekCloser, error) {
	return d.Open(d.prefix + key)
}

func (d *subStorage) Execute(fn func(tx Transaction) error) error {
	return d.db.Execute(func(tx Transaction) error {
		return fn(&subTransaction{d.prefix, tx})
	})
}

func (t *subTransaction) Put(key string, value io.Reader) error {
	return t.tx.Put(t.prefix+key, value)
}

func (t *subTransaction) Delete(key string) error {
	return t.tx.Delete(t.prefix + key)
}
