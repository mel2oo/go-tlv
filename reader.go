package tlv

import (
	"encoding/binary"
	"errors"
	"reflect"
)

// Errors introduced by encoding and decoding.
var (
	ErrPacketTooLarge = errors.New("exceed max size")
	ErrNotSupported   = errors.New("feature not supported")
	ErrUnexpectedType = errors.New("type not match")
	ErrInvalidPtr     = errors.New("invalid pointer")
)

func readVarNum(b []byte) (n int, v uint64) {
	switch b[0] {
	case 0xFF:
		v = binary.BigEndian.Uint64(b[1:])
		n = 9
	case 0xFE:
		v = uint64(binary.BigEndian.Uint32(b[1:]))
		n = 5
	case 0xFD:
		v = uint64(binary.BigEndian.Uint16(b[1:]))
		n = 3
	default:
		v = uint64(b[0])
		n = 1
	}
	return
}

func readUint64(b []byte) uint64 {
	switch len(b) {
	case 8:
		return binary.BigEndian.Uint64(b)
	case 4:
		return uint64(binary.BigEndian.Uint32(b))
	case 2:
		return uint64(binary.BigEndian.Uint16(b))
	case 1:
		return uint64(b[0])
	}
	return 0
}

func readStruct(v []byte, structValue reflect.Value) error {
	var n int
	return walkStruct(structValue.Type(), func(tag *structTag, i int) error {
		nn, err := readTLV(v[n:], tag.Type, structValue.Field(i))
		if err != nil && !tag.Optional {
			return err
		}
		n += nn
		return nil
	})
}

func readValue(v []byte, value reflect.Value) error {
	switch value.Kind() {
	case reflect.Bool:
		value.SetBool(true)
	case reflect.Uint64:
		value.SetUint(readUint64(v))
	case reflect.Slice:
		switch value.Type().Elem().Kind() {
		case reflect.Uint8:
			if len(v) == 0 {
				return nil
			}
			b := make([]byte, len(v))
			copy(b, v)
			value.SetBytes(b)
		default:
			i0 := value.Len()
			value.SetLen(i0 + 1)
			err := readValue(v, value.Index(i0))
			if err != nil {
				value.SetLen(i0)
				return err
			}
		}
	case reflect.String:
		value.SetString(string(v))
	case reflect.Ptr:
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		return readValue(v, value.Elem())
	case reflect.Struct:
		return readStruct(v, value)
	default:
		return ErrNotSupported
	}
	return nil
}

func countTLV(b []byte, expectType uint64, mult bool) (count int) {
	var n int
	for len(b[n:]) != 0 {
		nn, t := readVarNum(b[n:])
		if t != expectType {
			break
		}
		n += nn
		nn, l := readVarNum(b[n:])
		n += nn + int(l)
		count++

		if !mult {
			break
		}
	}
	return
}

// readTLV reads current tlv block if the type number matches.
//
// If reflect.Value is type of slice but not []byte, it will
// continue to read until the type number does not match.
func readTLV(b []byte, expectType uint64, value reflect.Value) (n int, err error) {
	isSlice := value.Kind() == reflect.Slice && value.Type().Elem().Kind() != reflect.Uint8

	count := countTLV(b, expectType, isSlice)
	if count == 0 {
		if value.Kind() == reflect.Bool || isSlice {
			return
		}
		err = ErrUnexpectedType
		return
	}
	if isSlice {
		value.Set(reflect.MakeSlice(value.Type(), 0, count))
	}

	for i := 0; i < count; i++ {
		nn, _ := readVarNum(b[n:])
		n += nn
		nn, l := readVarNum(b[n:])
		n += nn
		v := b[n : n+int(l)]
		n += int(l)
		err = readValue(v, value)
		if err != nil {
			return
		}
	}
	return
}
