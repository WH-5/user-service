package pkg

import "reflect"

// IsZeroValue 传入一个非 nil 的值,判断是否为本身类型的零值
func IsZeroValue(v any) bool {
	val := reflect.ValueOf(v)
	return val.IsValid() && val.Interface() == reflect.Zero(val.Type()).Interface()
}
