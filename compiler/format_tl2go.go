package main

import (
	"fmt"
	"io"
	"reflect"
	"strconv"
	"text/tabwriter"

	"github.com/kr/text"
)

const (
	limit = 50
)

type formatter struct {
	x     interface{}
	force bool
	quote bool
}

// Formatter makes a wrapper, f, that will format x as go source with line
// breaks and tabs. Object f responds to the "%v" formatting verb when both the
// "#" and " " (space) flags are set, for example:
//
//     fmt.Sprintf("%# v", Formatter(x))
//
// If one of these two flags is not set, or any other verb is used, f will
// format x according to the usual rules of package fmt.
// In particular, if x satisfies fmt.Formatter, then x.Format will be called.
func Formatter(x interface{}) (f fmt.Formatter) {
	return formatter{x: x, quote: true}
}

func (fo formatter) String() string {
	return fmt.Sprint(fo.x) // unwrap it
}

func (fo formatter) passThrough(f fmt.State, c rune) {
	s := "%"
	for i := 0; i < 128; i++ {
		if f.Flag(i) {
			s += string(i)
		}
	}
	if w, ok := f.Width(); ok {
		s += fmt.Sprintf("%d", w)
	}
	if p, ok := f.Precision(); ok {
		s += fmt.Sprintf(".%d", p)
	}
	s += string(c)
	fmt.Fprintf(f, s, fo.x)
}

func (fo formatter) Format(f fmt.State, c rune) {
	if fo.force || c == 'v' && f.Flag('#') && f.Flag(' ') {
		w := tabwriter.NewWriter(f, 4, 4, 1, ' ', 0)
		p := &printer{tw: w, Writer: w}
		p.printValue(reflect.ValueOf(fo.x), true, fo.quote)
		w.Flush()
		return
	}
	fo.passThrough(f, c)
}

type printer struct {
	io.Writer
	tw *tabwriter.Writer
}

func (p *printer) indent() *printer {
	q := *p
	q.tw = tabwriter.NewWriter(p.Writer, 4, 4, 1, ' ', 0)
	q.Writer = text.NewIndentWriter(q.tw, []byte{'\t'})
	return &q
}

func (p *printer) printInline(v reflect.Value, x interface{}, showType bool) {
	if showType {
		io.WriteString(p, v.Type().String())
		fmt.Fprintf(p, "(%#v)", x)
	} else {
		fmt.Fprintf(p, "%#v", x)
	}
}

// isProtobufField checks if a field has protobuf tags, indicating it's a real protobuf field
func isProtobufField(field reflect.StructField) bool {
	_, hasProtobuf := field.Tag.Lookup("protobuf")
	_, hasProtogen := field.Tag.Lookup("protogen")
	return hasProtobuf || hasProtogen
}

// isInternalProtobufField checks if this is an internal protobuf implementation field
func isInternalProtobufField(field reflect.StructField) bool {
	// Check for protogen tag indicating internal fields
	if protogen, ok := field.Tag.Lookup("protogen"); ok && protogen == "open.v1" {
		return true
	}
	
	// Check for known internal field types
	fieldType := field.Type.String()
	return fieldType == "protoimpl.MessageState" || 
		   fieldType == "protoimpl.UnknownFields" || 
		   fieldType == "protoimpl.SizeCache"
}

// shouldIncludeField determines if a field should be included in the output
func shouldIncludeField(field reflect.StructField, fieldValue reflect.Value) bool {
	// Skip unexported fields
	if field.Name == "" || !field.IsExported() {
		return false
	}
	
	// If this is a protobuf struct, use protobuf-aware logic
	if isProtobufField(field) {
		// Skip internal protobuf fields
		if isInternalProtobufField(field) {
			return false
		}
		
		// Include protobuf fields that have data OR are slices (even empty ones)
		if fieldValue.Kind() == reflect.Slice || fieldValue.Kind() == reflect.Array {
			return true // Always include slices for complete struct definition
		}
		
		return nonzero(fieldValue)
	}
	
	// For non-protobuf structs, use original logic
	return nonzero(fieldValue)
}

func (p *printer) printValue(v reflect.Value, showType, quote bool) {
	p.printValueWithContext(v, showType, quote, false)
}

func (p *printer) printValueWithContext(v reflect.Value, showType, quote, inPointerSlice bool) {
	switch v.Kind() {
	case reflect.Bool:
		p.printInline(v, v.Bool(), showType)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		p.printInline(v, v.Int(), showType)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		p.printInline(v, v.Uint(), showType)
	case reflect.Float32, reflect.Float64:
		p.printInline(v, v.Float(), showType)
	case reflect.Complex64, reflect.Complex128:
		fmt.Fprintf(p, "%#v", v.Complex())
	case reflect.String:
		p.fmtString(v.String(), quote)
	case reflect.Map:
		t := v.Type()
		if showType {
			io.WriteString(p, t.String())
		}
		writeByte(p, '{')
		if nonzero(v) {
			expand := !canInline(v.Type())
			pp := p
			if expand {
				writeByte(p, '\n')
				pp = p.indent()
			}
			keys := v.MapKeys()
			for i := 0; i < v.Len(); i++ {
				showTypeInStruct := true
				k := keys[i]
				mv := v.MapIndex(k)
				pp.printValue(k, false, true)
				writeByte(pp, ':')
				if expand {
					writeByte(pp, '\t')
				}
				showTypeInStruct = t.Elem().Kind() == reflect.Interface
				pp.printValueWithContext(mv, showTypeInStruct, true, false)
				if expand {
					io.WriteString(pp, ",\n")
				} else if i < v.Len()-1 {
					io.WriteString(pp, ", ")
				}
			}
			if expand {
				pp.tw.Flush()
			}
		}
		writeByte(p, '}')
	case reflect.Struct:
		t := v.Type()
		if showType {
			io.WriteString(p, t.String())
		}
		writeByte(p, '{')
		
		// Check if this struct has any protobuf fields to determine if we should apply protobuf logic
		hasProtobufFields := false
		for i := 0; i < v.NumField(); i++ {
			if field := t.Field(i); isProtobufField(field) {
				hasProtobufFields = true
				break
			}
		}
		
		if nonzero(v) || hasProtobufFields {
			expand := !canInline(v.Type())
			pp := p
			if expand {
				writeByte(p, '\n')
				pp = p.indent()
			}
			
			validFieldCount := 0
			for i := 0; i < v.NumField(); i++ {
				field := t.Field(i)
				fieldValue := getField(v, i)
				
				if shouldIncludeField(field, fieldValue) {
					if validFieldCount > 0 {
						if expand {
							io.WriteString(pp, ",\n")
						} else {
							io.WriteString(pp, ", ")
						}
					}
					
					showTypeInStruct := true
					io.WriteString(pp, field.Name)
					writeByte(pp, ':')
					if expand {
						writeByte(pp, '\t')
					}
					showTypeInStruct = field.Type.Kind() == reflect.Interface
					pp.printValueWithContext(fieldValue, showTypeInStruct, true, false)
					validFieldCount++
				}
			}
			if expand && validFieldCount > 0 {
				pp.tw.Flush()
			}
		}
		writeByte(p, '}')
	case reflect.Interface:
		switch e := v.Elem(); {
		case e.Kind() == reflect.Invalid:
			io.WriteString(p, "nil")
		case e.IsValid():
			p.printValueWithContext(e, showType, true, inPointerSlice)
		default:
			io.WriteString(p, v.Type().String())
			io.WriteString(p, "(nil)")
		}
	case reflect.Array, reflect.Slice:
		t := v.Type()
		// Always show slice type for non-empty slices when not already showing type
		if !showType && v.Len() > 0 {
			io.WriteString(p, t.String())
		} else if showType {
			io.WriteString(p, t.String())
		}
		
		if v.IsNil() && showType {
			io.WriteString(p, "(nil)")
			break
		}
		if v.IsNil() {
			io.WriteString(p, "nil")
			break
		}
		
		// For empty slices, show the type and empty braces
		if v.Len() == 0 {
			if !showType {
				// When we're inside a struct field, show the slice type for clarity
				io.WriteString(p, t.String())
			}
			io.WriteString(p, "{}")
			break
		}
		
		writeByte(p, '{')
		expand := !canInline(v.Type())
		pp := p
		if expand {
			writeByte(p, '\n')
			pp = p.indent()
		}
		for i := 0; i < v.Len(); i++ {
			// For slices of pointers, pass context to avoid redundant &Type{}
			isPointerSlice := t.Elem().Kind() == reflect.Ptr
			showTypeInSlice := t.Elem().Kind() == reflect.Interface
			pp.printValueWithContext(v.Index(i), showTypeInSlice, true, isPointerSlice)
			if expand {
				io.WriteString(pp, ",\n")
			} else if i < v.Len()-1 {
				io.WriteString(pp, ", ")
			}
		}
		if expand {
			pp.tw.Flush()
		}
		writeByte(p, '}')
	case reflect.Ptr:
		e := v.Elem()
		if !e.IsValid() {
			writeByte(p, '(')
			io.WriteString(p, v.Type().String())
			io.WriteString(p, ")(nil)")
		} else {
			// Only skip the '&' prefix when we're inside a slice of pointers
			if !inPointerSlice {
				writeByte(p, '&')
			}
			p.printValueWithContext(e, !inPointerSlice, true, false)
		}
	case reflect.Chan:
		x := v.Pointer()
		if showType {
			writeByte(p, '(')
			io.WriteString(p, v.Type().String())
			fmt.Fprintf(p, ")(%#v)", x)
		} else {
			fmt.Fprintf(p, "%#v", x)
		}
	case reflect.Func:
		io.WriteString(p, v.Type().String())
		io.WriteString(p, " {...}")
	case reflect.UnsafePointer:
		p.printInline(v, v.Pointer(), showType)
	case reflect.Invalid:
		io.WriteString(p, "nil")
	}
}

func canInline(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Map:
		return !canExpand(t.Elem())
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if canExpand(t.Field(i).Type) {
				return false
			}
		}
		return true
	case reflect.Interface:
		return false
	case reflect.Array, reflect.Slice:
		return !canExpand(t.Elem())
	case reflect.Ptr:
		return false
	case reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return false
	}
	return true
}

func canExpand(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Map, reflect.Struct,
		reflect.Interface, reflect.Array, reflect.Slice,
		reflect.Ptr:
		return true
	}
	return false
}

func (p *printer) fmtString(s string, quote bool) {
	if quote {
		s = strconv.Quote(s)
	}
	io.WriteString(p, s)
}

func tryDeepEqual(a, b interface{}) bool {
	defer func() { recover() }()
	return reflect.DeepEqual(a, b)
}

func writeByte(w io.Writer, b byte) {
	w.Write([]byte{b})
}

func getField(v reflect.Value, i int) reflect.Value {
	val := v.Field(i)
	if val.Kind() == reflect.Interface && !val.IsNil() {
		val = val.Elem()
	}
	return val
}

func nonzero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Bool:
		return v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() != 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() != 0
	case reflect.Float32, reflect.Float64:
		return v.Float() != 0
	case reflect.Complex64, reflect.Complex128:
		return v.Complex() != complex(0, 0)
	case reflect.String:
		return v.String() != ""
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if nonzero(getField(v, i)) {
				return true
			}
		}
		return false
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if nonzero(v.Index(i)) {
				return true
			}
		}
		return false
	case reflect.Map, reflect.Interface, reflect.Slice, reflect.Ptr, reflect.Chan, reflect.Func:
		return !v.IsNil()
	case reflect.UnsafePointer:
		return v.Pointer() != 0
	}
	return true
}
