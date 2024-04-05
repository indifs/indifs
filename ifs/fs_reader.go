package ifs

import "io"

type filesReader struct {
	ff []fileOpenFunc
	r  io.ReadCloser
}

type fileOpenFunc func() (io.ReadCloser, error)

func newFilesReader() *filesReader {
	return &filesReader{}
}

func (f *filesReader) add(fn fileOpenFunc) {
	f.ff = append(f.ff, fn)
}

func (f *filesReader) Read(buf []byte) (n int, err error) {
	for len(buf) > 0 && len(f.ff) > 0 {
		if f.r == nil {
			if f.r, err = f.ff[0](); err != nil {
				return n, err
			}
			f.ff = f.ff[1:]
		}
		var m int
		if m, err = f.r.Read(buf); err == io.EOF {
			f.r, err = nil, f.r.Close()
		}
		n += m
		if err != nil {
			return
		}
		buf = buf[m:]
	}
	if len(buf) > 0 {
		err = io.EOF
	}
	return
}

func (f *filesReader) Close() (err error) {
	f.ff = nil
	if f.r != nil {
		f.r, err = nil, f.r.Close()
	}
	return
}
