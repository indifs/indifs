package indifs

import "io"

type multiReader struct {
	ff []openReaderFunc
	r  io.ReadCloser
}

type openReaderFunc = func() (io.ReadCloser, error)

func newMultiReader() *multiReader {
	return &multiReader{}
}

func (f *multiReader) add(fn openReaderFunc) {
	f.ff = append(f.ff, fn)
}

func (f *multiReader) Read(buf []byte) (n int, err error) {
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

func (f *multiReader) Close() (err error) {
	f.ff = nil
	if f.r != nil {
		f.r, err = nil, f.r.Close()
	}
	return
}
