package main

import (
	"fmt"
	"reflect"
	"strings"
)

func parseInvokeWithLayer(obj interface{}) {
	// Check if this is invokeWithLayer
	objStr := fmt.Sprintf("%v", obj)
	if !strings.Contains(objStr, "CRC32_invokeWithLayer") {
		return
	}
	
	fmt.Println("Object string:", objStr)
	fmt.Println("Object type:", reflect.TypeOf(obj))
	
	// Try to access fields using reflection
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	
	if v.Kind() == reflect.Struct {
		t := v.Type()
		fmt.Println("Number of fields:", v.NumField())
		for i := 0; i < v.NumField(); i++ {
			field := t.Field(i)
			value := v.Field(i)
			fmt.Printf("Field %d: Name=%s, Type=%v, Value=%v\n", i, field.Name, field.Type, value.Interface())
		}
	}
}