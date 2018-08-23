package reflect

import (
	"reflect"
	"unsafe"
)

// SetFieldValue sets value on the field of the given reflected value
func SetFieldValue(p reflect.Value, name string, value interface{}) {
	field := p.FieldByName(name)
	field = reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	field.Set(reflect.ValueOf(value))
}

// FieldToInterface gets a interface for a field of a given reflected value
func FieldToInterface(p reflect.Value, name string) interface{} {
	field := p.FieldByName(name)
	field = reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	return field.Interface()
}
