package database

import (
	"errors"
	"io"
)

type Storage interface {
	OpenAt(table, key string, offset int64) (io.ReadCloser, error)
	Execute(table string, fn func(tx Transaction) error) error
	Drop(table string) error
}

type Transaction interface {
	Put(key string, size int64, r io.Reader) error
	Delete(key string) error
}

var ErrNotFound = errors.New("db-error: not found")
