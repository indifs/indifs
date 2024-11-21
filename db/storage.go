package db

import (
	"bytes"
	"encoding/json"
	"io"
)

type Storage interface {
	Open(key string) (io.ReadSeekCloser, error)
	Execute(func(tx Transaction) error) error
}

type Transaction interface {
	Put(key string, value io.Reader) error
	Delete(key string) error
}

func GetJSON(db Storage, key string, v any) (err error) {
	if jsonDB, ok := db.(interface {
		GetJSON(key string, v any) error
	}); ok {
		return jsonDB.GetJSON(key, v)
	}
	fl, err := db.Open(key)
	if err != nil || fl == nil {
		return
	}
	defer fl.Close()
	data, err := io.ReadAll(fl)
	if err != nil || len(data) == 0 {
		return
	}
	return json.Unmarshal(data, v)
}

func PutJSON(tx Transaction, key string, v any) error {
	if jsonDB, ok := tx.(interface {
		PutJSON(key string, v any) error
	}); ok {
		return jsonDB.PutJSON(key, v)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return tx.Put(key, bytes.NewBuffer(b))
}
