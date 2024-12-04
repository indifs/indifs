package indifs

import (
	"fmt"
	"runtime"
	"testing"
)

func Test_dirname(t *testing.T) {
	assert(t, dirname("") == "")
	assert(t, dirname("/") == "")
	assert(t, dirname("/a.txt") == "/")
	assert(t, dirname("/aa/") == "/")
	assert(t, dirname("/aa/bb") == "/aa/")
	assert(t, dirname("/aa/bb/cc.txt") == "/aa/bb/")
}

func Test_splitPath(t *testing.T) {
	assert(t, equal(splitPath(""), nil))
	assert(t, equal(splitPath("/"), nil))
	assert(t, equal(splitPath("/Hello/世界/Abc01.txt"), []string{"Hello", "世界", "Abc01.txt"}))
}

func Test_sortHeaders(t *testing.T) {
	newHeader := func(path string) Header { return Header{{Name: "Path", Value: []byte(path)}} }

	hh := []Header{
		newHeader("/abc/"),
		newHeader("/def/2.txt"),
		newHeader("/abc/1.txt"),
		newHeader(""),
		newHeader("/def/1.txt"),
		newHeader("/def/"),
		newHeader("/"),
		newHeader("/abc/2.txt"),
	}

	sortHeaders(hh)

	assert(t, equal(hh, []Header{
		newHeader(""),
		newHeader("/"),
		newHeader("/abc/"),
		newHeader("/abc/1.txt"),
		newHeader("/abc/2.txt"),
		newHeader("/def/"),
		newHeader("/def/1.txt"),
		newHeader("/def/2.txt"),
	}))
}

func Test_IsValidPath(t *testing.T) {
	assert(t, IsValidPath("/"))
	assert(t, IsValidPath("/aaa/123_456-7890/Abc01.txt"))
	assert(t, IsValidPath("/Hello, 世界/Abc01.txt"))
	assert(t, IsValidPath("/Hello, 世界/Abc..01.txt"))
	assert(t, IsValidPath("/~/@/-/a../_/Abc01.txt"))
	assert(t, IsValidPath("/aaa/111..-0/Abc01.txt"))
	assert(t, IsValidPath("/1/2/3/4/5/Abc01.txt"))
	assert(t, IsValidPath("/aaa/123456789-123456789-123456789-123456789-123456789-/Abc01.txt"))
	assert(t, IsValidPath("/aaa/.111-0/Abc01.txt"))
	assert(t, IsValidPath("/"+
		"-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789"+
		"-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789"+
		"-123456789-123456789-123456789-123456789-123456789"+
		"1.txt",
	)) // path-length == 255
	assert(t, IsValidPath("/aaa/.Abc01.txt"))

	assert(t, !IsValidPath(""))
	assert(t, !IsValidPath("/aaa/..Abc01.txt"))
	assert(t, !IsValidPath("/aaa/  /Abc01.txt"))
	assert(t, !IsValidPath("/aaa//Abc01.txt"))
	assert(t, !IsValidPath("/aaa/./Abc01.txt"))
	assert(t, !IsValidPath("/aaa/../Abc01.txt"))
	assert(t, !IsValidPath("/aaa/.../Abc01.txt"))
	assert(t, !IsValidPath("/1/2/3/4/5/A/bc01.txt"))
	assert(t, !IsValidPath("/"+
		"123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-"+
		"123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-"+
		"123456789-123456789-123456789-123456789-123456789-12.txt",
	)) // path-length == 256
}

func assert(t *testing.T, ok bool) {
	if !ok {
		//t.Fail()
		_, file, line, _ := runtime.Caller(1)
		//t.Logf("ASSERT-ERROR %s:%d", file, line)
		t.Errorf("ASSERT-ERROR %s:%d", file, line)
		panic("assert-error")
	}
}

func trace(title string, v any) {
	//_, file, line, _ := runtime.Caller(1)
	//log.Panic(fmt.Errorf("%w\n\t%s:%d", err, file, line))
	println(title)
	if v, ok := v.(interface{ Trace() }); ok {
		v.Trace()
		return
	}
	println("====== TRACE: ", toIndentJSON(v))
}

func equal(a, b any) bool {
	return equalJSON(toJSON(a), toJSON(b))
}

func equalJSON(a, b string) bool {
	return a == b || toJSON(decodeJSON(a)) == toJSON(decodeJSON(b))
}

func init() {
	_checkError = func(err error) {
		if err != nil {
			_, file, line, _ := runtime.Caller(2)
			//log.Panic(fmt.Errorf("%w\n\t%s:%d", err, file, line))
			panic(fmt.Errorf("%w\n\t%s:%d", err, file, line))
		}
	}
}
