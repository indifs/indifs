package ifs

import "testing"

func Test_dirname(t *testing.T) {
	assert(t, "" == dirname("/"))
	assert(t, "/" == dirname("/a.txt"))
	assert(t, "/" == dirname("/aa/"))
	assert(t, "/aa/" == dirname("/aa/bb"))
	assert(t, "/aa/bb/" == dirname("/aa/bb/cc.txt"))
}

func Test_splitPath(t *testing.T) {
	assertEq(t, splitPath("/Hello/世界/Abc01.txt"), []any{"Hello", "世界", "Abc01.txt"})
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
		//t.Fatal()
		panic(0)
		//panic(string(debug.Stack()))
	}
}

func assertEq(t *testing.T, a, b any) {
	assert(t, equalJSON(toJSON(a), toJSON(b)))
}

func equalJSON(a, b string) bool {
	return a == b || toJSON(decodeJSON(a)) == toJSON(decodeJSON(b))
}
