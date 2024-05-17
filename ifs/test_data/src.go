package test_data

import (
	"embed"
	"io/fs"
)

//go:embed *
var src embed.FS

func FS(name string) fs.FS {
	f, err := fs.Sub(src, name)
	if err != nil {
		panic(err)
	}
	return f
}
