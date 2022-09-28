package tlv

import (
	"reflect"
)

// Marshal returns the tlv encoding of v.
//
// The "tlv" struct tag specifies tlv type number.
// '?' after type number indicates that this tlv
// should be omitted if the value is empty.
func Marshal(v interface{}, t uint64) (b []byte, err error) {
	b, err = writeTLV(b, t, reflect.ValueOf(v), false)
	if err != nil {
		return
	}
	return
}
