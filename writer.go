package tlv

import (
	"encoding/binary"
	"math"
	"reflect"
)

func writeVarNum(b []byte, v uint64) []byte {
	tmp := make([]byte, 8)
	n := 0
	switch {
	case v > math.MaxUint32:
		b = append(b, 0xFF)
		binary.BigEndian.PutUint64(tmp, v)
		n = 8
	case v > math.MaxUint16:
		b = append(b, 0xFE)
		binary.BigEndian.PutUint32(tmp, uint32(v))
		n = 4
	case v > math.MaxUint8-3:
		b = append(b, 0xFD)
		binary.BigEndian.PutUint16(tmp, uint16(v))
		n = 2
	default:
		b = append(b, uint8(v))
		return b
	}
	b = append(b, tmp[:n]...)
	return b
}

func writeUint64(b []byte, v uint64) []byte {
	tmp := make([]byte, 8)
	n := 0
	switch {
	case v > math.MaxUint32:
		b = append(b, 8)
		binary.BigEndian.PutUint64(tmp, v)
		n = 8
	case v > math.MaxUint16:
		b = append(b, 4)
		binary.BigEndian.PutUint32(tmp, uint32(v))
		n = 4
	case v > math.MaxUint8:
		b = append(b, 2)
		binary.BigEndian.PutUint16(tmp, uint16(v))
		n = 2
	default:
		b = append(b, 1)
		b = append(b, uint8(v))
		return b
	}
	b = append(b, tmp[:n]...)
	return b
}

func writeUintValue(b []byte, v uint64, kind reflect.Kind) []byte {
	tmp := make([]byte, 8)
	n := 0
	switch kind {
	case reflect.Uint64:
		binary.BigEndian.PutUint64(tmp, v)
		n = 8
	case reflect.Uint32:
		binary.BigEndian.PutUint32(tmp, uint32(v))
		n = 4
	case reflect.Uint16:
		binary.BigEndian.PutUint16(tmp, uint16(v))
		n = 2
	default:
		b = append(b, uint8(v))
		return b
	}
	b = append(b, tmp[:n]...)
	return b
}

func writeStruct(b []byte, structValue reflect.Value, noSignature bool) ([]byte, error) {
	var err error
	err = walkStruct(structValue.Type(), func(tag *structTag, i int) error {
		fieldValue := structValue.Field(i)
		if tag.Signature && noSignature ||
			tag.Optional && isZero(fieldValue) {
			return nil
		}
		b, err = writeTLV(b, tag.Type, fieldValue, noSignature)
		if err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		return b, err
	}
	return b, nil
}

func writeTLV(b []byte, t uint64, value reflect.Value, noSignature bool) ([]byte, error) {
	var err error
	switch value.Kind() {
	case reflect.Bool:
		if value.Bool() {
			b = writeVarNum(b, t)
			b = append(b, 0)
		}
	case reflect.Uint64:
		b = writeVarNum(b, t)
		b = writeUint64(b, value.Uint())
	case reflect.Slice:
		ele := value.Type().Elem()
		switch ele.Kind() {
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			b = writeVarNum(b, t)
			b = writeVarNum(b, uint64(value.Len()*int(ele.Size())))
			for j := 0; j < value.Len(); j++ {
				b = writeUintValue(b, value.Index(j).Uint(), ele.Kind())
			}
		default:
			for j := 0; j < value.Len(); j++ {
				b, err = writeTLV(b, t, value.Index(j), noSignature)
				if err != nil {
					return nil, err
				}
			}
		}
	case reflect.String:
		b = writeVarNum(b, t)
		v := value.String()
		b = writeVarNum(b, uint64(len(v)))
		b = append(b, v...)
	case reflect.Ptr:
		return writeTLV(b, t, value.Elem(), noSignature)
	case reflect.Struct:
		b = writeVarNum(b, t)
		var v []byte
		v, err = writeStruct(v, value, noSignature)
		if err != nil {
			return nil, err
		}
		b = writeVarNum(b, uint64(len(v)))
		b = append(b, v...)
	default:
		err = ErrNotSupported
	}
	return b, err
}
