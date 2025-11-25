package main

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
)

// GoCodeFormatter wraps mpretty-style formatting to generate compilable Go code
type GoCodeFormatter struct {
	buf *bytes.Buffer
}

func NewGoCodeFormatter() *GoCodeFormatter {
	return &GoCodeFormatter{buf: &bytes.Buffer{}}
}

func (f *GoCodeFormatter) Format(v interface{}) string {
	f.buf.Reset()
	f.writeValue(reflect.ValueOf(v), "", true)
	return f.buf.String()
}

func (f *GoCodeFormatter) writeValue(v reflect.Value, indent string, showType bool) {
	if !v.IsValid() || (v.Kind() == reflect.Ptr && v.IsNil()) {
		f.buf.WriteString("nil")
		return
	}

	switch v.Kind() {
	case reflect.Ptr:
		f.buf.WriteString("&")
		f.writeValue(v.Elem(), indent, true)
		
	case reflect.Struct:
		if showType {
			typeName := v.Type().String()
			typeName = strings.ReplaceAll(typeName, "github.com/teamgram/proto/", "")
			typeName = strings.ReplaceAll(typeName, "google.golang.org/protobuf/types/known/", "")
			f.buf.WriteString(typeName)
		}
		f.buf.WriteString("{\n")
		
		// Special case for TLContactsImportedContacts - expand Data2 inline
		if strings.Contains(v.Type().Name(), "TLContactsImportedContacts") {
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).Name == "Data2" && v.Field(i).Kind() == reflect.Ptr && !v.Field(i).IsNil() {
					f.writeStructFields(v.Field(i).Elem(), indent+"\t")
					break
				}
			}
		} else {
			f.writeStructFields(v, indent+"\t")
		}
		f.buf.WriteString(indent + "}")
		
	case reflect.Slice:
		elemType := v.Type().Elem()
		typeName := "[]" + elemType.String()
		if elemType.Kind() == reflect.Ptr {
			typeName = "[]*" + elemType.Elem().String()
		}
		typeName = strings.ReplaceAll(typeName, "github.com/teamgram/proto/", "")
		
		if v.Len() == 0 {
			f.buf.WriteString(typeName + "{}")
			return
		}
		
		f.buf.WriteString(typeName + "{\n")
		for i := 0; i < v.Len(); i++ {
			f.buf.WriteString(indent + "\t")
			if v.Index(i).Kind() == reflect.Ptr {
				f.writeValue(v.Index(i).Elem(), indent+"\t", false)
			} else {
				f.writeValue(v.Index(i), indent+"\t", false)
			}
			if i < v.Len()-1 {
				f.buf.WriteString(",")
			}
			f.buf.WriteString("\n")
		}
		f.buf.WriteString(indent + "}")
		
	case reflect.String:
		fmt.Fprintf(f.buf, "%q", v.String())
		
	case reflect.Bool, reflect.Int, reflect.Int32, reflect.Int64, reflect.Uint32, reflect.Uint64:
		fmt.Fprintf(f.buf, "%v", v.Interface())
		
	default:
		fmt.Fprintf(f.buf, "%#v", v.Interface())
	}
}

func (f *GoCodeFormatter) writeStructFields(v reflect.Value, indent string) {
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		if !field.IsExported() || field.Name == "state" || field.Name == "unknownFields" || field.Name == "sizeCache" {
			continue
		}
		
		f.buf.WriteString(fmt.Sprintf("%s%-22s ", indent, field.Name+":"))
		f.writeValue(v.Field(i), indent, true)
		if i < v.NumField()-1 {
			f.buf.WriteString(",")
		}
		f.buf.WriteString("\n")
	}
}

func GenerateGoCode(obj interface{}) string {
	formatter := NewGoCodeFormatter()
	return formatter.Format(obj)
}