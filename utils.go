package indifs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func require(f bool, err any) {
	if !f {
		_checkError(toError(err))
	}
}

func must(err error) {
	_checkError(err)
}

func mustVal[T any](v T, err error) T {
	_checkError(err)
	return v
}

func valExcludedNotFound[T any](v T, err error) T {
	if err != ErrNotFound {
		_checkError(err)
	}
	return v
}

var _checkError = func(err error) {
	if err != nil {
		panic(err)
	}
}

func recoverError(err *error) {
	if r := recover(); r != nil {
		*err = joinErrors(*err, toError(r))
	}
}

func catchError(fn func(error)) {
	if r := recover(); r != nil {
		fn(toError(r))
	}
}

func toError(err any) error {
	if e, ok := err.(error); ok {
		return e
	}
	return fmt.Errorf("%v", err)
}

func joinErrors(a, b error) error {
	if a == nil {
		return b
	}
	return errors.Join(a, b)
}

func containsOnly(s, chars string) bool {
	// todo: optimize, use charset-table as array  (see net/textproto/reader.go isTokenTable)
	for _, c := range s {
		if strings.IndexRune(chars, c) == -1 {
			return false
		}
	}
	return true
}

func sliceFilter[S ~[]E, E any](vv S, fn func(E) bool) (res S) {
	for _, v := range vv {
		if fn(v) {
			res = append(res, v)
		}
	}
	return
}

func bContainOnly(s, chars []byte) bool {
	for _, c := range s {
		if bytes.IndexByte(chars, c) == -1 {
			return false
		}
	}
	return true
}

func toJSON(v any) string {
	return string(mustVal(json.Marshal(v)))
}

func decodeJSON(data string) (v any) {
	must(json.Unmarshal([]byte(data), &v))
	return
}

func toIndentJSON(v any) string {
	return string(mustVal(json.MarshalIndent(v, "", "  ")))
}
