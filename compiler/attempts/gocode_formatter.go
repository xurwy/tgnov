package main

import (
	"fmt"
	"io"
	"reflect"
	"strings"
	"text/tabwriter"
	"github.com/kr/text"
)

// Simple Go code formatter based on mpretty's core
type goFormatter struct {
	v reflect.Value
}

type goPrinter struct {
	io.Writer
	tw    *tabwriter.Writer
	depth int
}

func GoFormatter(x interface{}) fmt.Formatter {
	return goFormatter{v: reflect.ValueOf(x)}
}

// GoFormatterNoType formats without showing the type name at the root level
func GoFormatterNoType(x interface{}) fmt.Formatter {
	return goFormatterNoType{v: reflect.ValueOf(x)}
}

type goFormatterNoType struct {
	v reflect.Value
}

func (fo goFormatterNoType) Format(f fmt.State, c rune) {
	if c == 'v' && f.Flag('#') && f.Flag(' ') {
		w := tabwriter.NewWriter(f, 4, 4, 1, ' ', 0)
		p := &goPrinter{tw: w, Writer: w}
		p.printValue(fo.v, false) // Don't show type at root
		w.Flush()
		return
	}
	fmt.Fprintf(f, "%v", fo.v.Interface())
}

func (fo goFormatter) Format(f fmt.State, c rune) {
	if c == 'v' && f.Flag('#') && f.Flag(' ') {
		w := tabwriter.NewWriter(f, 4, 4, 1, ' ', 0)
		p := &goPrinter{tw: w, Writer: w}
		p.printValue(fo.v, true)
		w.Flush()
		return
	}
	fmt.Fprintf(f, "%v", fo.v.Interface())
}

func (p *goPrinter) indent() *goPrinter {
	q := *p
	q.tw = tabwriter.NewWriter(p.Writer, 4, 4, 1, ' ', 0)
	q.Writer = text.NewIndentWriter(q.tw, []byte{'\t'})
	return &q
}

func (p *goPrinter) printValue(v reflect.Value, showType bool) {
	if p.depth > 10 {
		io.WriteString(p, "nil")
		return
	}

	if !v.IsValid() {
		io.WriteString(p, "nil")
		return
	}

	switch v.Kind() {
	case reflect.Bool:
		fmt.Fprintf(p, "%v", v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		fmt.Fprintf(p, "%d", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		fmt.Fprintf(p, "%d", v.Uint())
	case reflect.Float32, reflect.Float64:
		fmt.Fprintf(p, "%v", v.Float())
	case reflect.String:
		fmt.Fprintf(p, "%q", v.String())
	case reflect.Ptr:
		if v.IsNil() {
			io.WriteString(p, "nil")
		} else {
			io.WriteString(p, "&")
			p.depth++
			p.printValue(v.Elem(), true)
			p.depth--
		}
	case reflect.Struct:
		p.printStruct(v, showType)
	case reflect.Slice:
		p.printSlice(v, showType)
	case reflect.Interface:
		if v.IsNil() {
			io.WriteString(p, "nil")
		} else {
			p.printValue(v.Elem(), showType)
		}
	default:
		fmt.Fprintf(p, "%#v", v.Interface())
	}
}

func (p *goPrinter) printStruct(v reflect.Value, showType bool) {
	t := v.Type()
	
	if showType {
		typeName := p.cleanTypeName(t.String())
		io.WriteString(p, typeName)
	}
	io.WriteString(p, "{\n")
	
	pp := p.indent()
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() || p.shouldSkipField(field.Name) {
			continue
		}
		
		io.WriteString(pp, field.Name+":")
		io.WriteString(pp, "\t")
		pp.printValue(v.Field(i), true)
		io.WriteString(pp, ",\n")
	}
	pp.tw.Flush()
	io.WriteString(p, "}")
}

func (p *goPrinter) printSlice(v reflect.Value, showType bool) {
	if showType {
		typeName := p.cleanTypeName(v.Type().String())
		io.WriteString(p, typeName)
	}
	
	if v.IsNil() {
		io.WriteString(p, "(nil)")
		return
	}
	
	if v.Len() == 0 {
		io.WriteString(p, "{}")
		return
	}
	
	io.WriteString(p, "{\n")
	pp := p.indent()
	
	for i := 0; i < v.Len(); i++ {
		elem := v.Index(i)
		if elem.Kind() == reflect.Ptr && !elem.IsNil() {
			// For slice elements, show struct without type name
			io.WriteString(pp, "{\n")
			ppp := pp.indent()
			structVal := elem.Elem()
			for j := 0; j < structVal.NumField(); j++ {
				f := structVal.Type().Field(j)
				if !f.IsExported() || p.shouldSkipField(f.Name) {
					continue
				}
				io.WriteString(ppp, f.Name+":")
				io.WriteString(ppp, "\t")
				ppp.printValue(structVal.Field(j), true)
				io.WriteString(ppp, ",\n")
			}
			ppp.tw.Flush()
			io.WriteString(pp, "}")
		} else {
			pp.printValue(elem, false)
		}
		
		if i < v.Len()-1 {
			io.WriteString(pp, ",")
		}
		io.WriteString(pp, "\n")
	}
	
	pp.tw.Flush()
	io.WriteString(p, "}")
}

func (p *goPrinter) cleanTypeName(typeName string) string {
	typeName = strings.Replace(typeName, "github.com/teamgram/proto/", "", -1)
	typeName = strings.Replace(typeName, "google.golang.org/protobuf/types/known/", "", -1)
	return typeName
}

func (p *goPrinter) shouldSkipField(name string) bool {
	return name == "state" || name == "unknownFields" || name == "sizeCache"
}