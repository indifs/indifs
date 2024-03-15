package ifs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

var testMode = len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "-test.")

func tryVal[T any](v T, err error) T {
	try(err)
	return v
}

func tryVal2[T1, T2 any](v1 T1, v2 T2, err error) (T1, T2) {
	try(err)
	return v1, v2
}

func tryVal3[T1, T2, T3 any](v1 T1, v2 T2, v3 T3, err error) (T1, T2, T3) {
	try(err)
	return v1, v2, v3
}

func excludeErr(err, errConst error) error {
	if err == errConst {
		return nil
	}
	return err
}

func try(err error) {
	if err != nil {
		log.Panic(err)
		//_, file, line, _ := runtime.Caller(1)
		//log.Panic(fmt.Errorf("%w\n\t%s:%d", err, file, line))
	}
}

func require(f bool, err string) {
	if !f {
		try(errors.New(err))
	}
}

func catch(err *error) {
	//if testMode {
	//	return
	//}
	if r := recover(); r != nil {
		*err = joinErrors(*err, toError(r))
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

func bContainOnly(s, chars []byte) bool {
	for _, c := range s {
		if bytes.IndexByte(chars, c) == -1 {
			return false
		}
	}
	return true
}

func toJSON(v any) string {
	return string(tryVal(json.Marshal(v)))
}

func decodeJSON(data string) (v any) {
	try(json.Unmarshal([]byte(data), &v))
	return
}

func toIndentJSON(v any) string {
	return string(tryVal(json.MarshalIndent(v, "", "  ")))
}

func trace(title string, v any) {
	if !testMode {
		return
	}
	println(title)
	if v, ok := v.(interface{ Trace() }); ok {
		v.Trace()
		return
	}
	println("====== TRACE: ", toIndentJSON(v))
}
