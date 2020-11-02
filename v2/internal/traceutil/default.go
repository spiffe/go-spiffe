package traceutil

import (
	"reflect"
)

var (
	empty      interface{}
	emptyValue = reflect.ValueOf(&empty).Elem()
)

// SetNoopIfUnset fills in unset trace callbacks with noop functions. This
// simplifies trace related code by removing the need for an if statement to
// check if the callback is set before calling.
func SetNoopIfUnset(trace interface{}) {
	pv := reflect.ValueOf(trace)
	pt := pv.Type()

	if pt.Kind() != reflect.Ptr {
		return
	}

	sv := reflect.Indirect(pv)
	st := sv.Type()

	if st.Kind() != reflect.Struct {
		return
	}

	for i := 0; i < st.NumField(); i++ {
		fv := sv.Field(i)
		if !fv.IsZero() {
			continue
		}

		fnType := st.Field(i).Type
		fv.Set(reflect.MakeFunc(fnType, func([]reflect.Value) []reflect.Value {
			var out []reflect.Value
			for i := 0; i < fnType.NumOut(); i++ {
				out = append(out, emptyValue)
			}
			return out
		}))
	}
}
