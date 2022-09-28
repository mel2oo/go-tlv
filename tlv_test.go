package tlv

import (
	"fmt"
	"testing"
)

func TestTLV(t *testing.T) {

	type testStruct struct {
		Small   uint64 `tlv:"1"`
		Middle  uint64 `tlv:"2"`
		Big     uint64 `tlv:"3"`
		BoolVar bool   `tlv:"4"`
		Str     string `tlv:"5"`
		Byte    []byte `tlv:"6"`
	}

	x := [...]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	test1 := &testStruct{
		Small:   1,
		Middle:  65536,
		Big:     1 << 32,
		BoolVar: true,
		Str:     "",
		Byte:    x[:],
	}
	ret, err := Marshal(test1, 1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%v", ret)
}
