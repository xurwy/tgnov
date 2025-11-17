package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/teamgram/proto/mtproto"
)

// formatObject provides custom formatting with depth limit to avoid getting stuck on large objects
func formatObject(obj interface{}, maxDepth int) string {
	return formatObjectRecursive(obj, 0, maxDepth, make(map[uintptr]bool))
}

func formatObjectRecursive(obj interface{}, depth, maxDepth int, visited map[uintptr]bool) string {
	if depth > maxDepth {
		return "..."
	}

	v := reflect.ValueOf(obj)
	if !v.IsValid() {
		return "nil"
	}

	// Handle pointers
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return "nil"
		}
		// Check for circular references
		ptr := v.Pointer()
		if visited[ptr] {
			return "<circular>"
		}
		visited[ptr] = true
		defer delete(visited, ptr)
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Struct:
		t := v.Type()
		var parts []string
		indent := strings.Repeat("  ", depth)
		fieldIndent := strings.Repeat("  ", depth+1)
		
		parts = append(parts, t.Name()+"{")
		
		for i := 0; i < v.NumField(); i++ {
			field := t.Field(i)
			fieldValue := v.Field(i)
			
			// Skip unexported fields
			if field.PkgPath != "" {
				continue
			}
			
			// Skip zero values for cleaner output
			if isZeroValue(fieldValue) {
				continue
			}
			
			formatted := formatObjectRecursive(fieldValue.Interface(), depth+1, maxDepth, visited)
			// Handle multiline formatted values
			if strings.Contains(formatted, "\n") {
				lines := strings.Split(formatted, "\n")
				indentedLines := make([]string, len(lines))
				for j, line := range lines {
					if j == 0 {
						indentedLines[j] = line
					} else {
						indentedLines[j] = fieldIndent + line
					}
				}
				formatted = strings.Join(indentedLines, "\n")
			}
			parts = append(parts, fmt.Sprintf("%s%s: %s", fieldIndent, field.Name, formatted))
		}
		
		parts = append(parts, indent+"}")
		return strings.Join(parts, "\n")
		
	case reflect.Slice, reflect.Array:
		if v.Len() == 0 {
			return "[]"
		}
		if v.Len() > 10 {
			return fmt.Sprintf("[%d items]", v.Len())
		}
		var items []string
		for i := 0; i < v.Len() && i < 10; i++ {
			items = append(items, formatObjectRecursive(v.Index(i).Interface(), depth+1, maxDepth, visited))
		}
		return "[" + strings.Join(items, ", ") + "]"
		
	case reflect.Map:
		if v.Len() == 0 {
			return "{}"
		}
		if v.Len() > 10 {
			return fmt.Sprintf("map[%d items]", v.Len())
		}
		var items []string
		for _, key := range v.MapKeys() {
			if len(items) >= 10 {
				items = append(items, "...")
				break
			}
			keyStr := formatObjectRecursive(key.Interface(), depth+1, maxDepth, visited)
			valStr := formatObjectRecursive(v.MapIndex(key).Interface(), depth+1, maxDepth, visited)
			items = append(items, fmt.Sprintf("%s: %s", keyStr, valStr))
		}
		return "{" + strings.Join(items, ", ") + "}"
		
	case reflect.String:
		s := v.String()
		if len(s) > 100 {
			return fmt.Sprintf("\"%s...\" [%d chars]", s[:100], len(s))
		}
		return fmt.Sprintf("%q", s)
		
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fmt.Sprintf("%d", v.Int())
		
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fmt.Sprintf("%d", v.Uint())
		
	case reflect.Float32, reflect.Float64:
		return fmt.Sprintf("%g", v.Float())
		
	case reflect.Bool:
		return fmt.Sprintf("%t", v.Bool())
		
	case reflect.Interface:
		if v.IsNil() {
			return "nil"
		}
		return formatObjectRecursive(v.Elem().Interface(), depth, maxDepth, visited)
		
	default:
		return fmt.Sprintf("<%s>", v.Kind())
	}
}

func isZeroValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Slice, reflect.Map, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return false
}

func processQuery(queryBytes []byte, out *os.File, indent string) {
	if len(queryBytes) == 0 { return }
	queryBuf := mtproto.NewDecodeBuf(queryBytes)
	if queryObj := queryBuf.Object(); queryObj != nil {
		fmt.Fprintf(out, "%sQuery: %s\n", indent, queryObj.String())
		v := reflect.ValueOf(queryObj)
		if v.Kind() == reflect.Ptr { v = v.Elem() }
		if v.Kind() == reflect.Struct {
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).Name == "Query" {
					if value := v.Field(i); value.IsValid() && !value.IsNil() {
						if qBytes, ok := value.Interface().([]byte); ok && len(qBytes) > 0 {
							processQuery(qBytes, out, indent + "  ")
						}
					}
					break
				}
			}
		}
	}
}

func main() {
	out, _ := os.Create("tl_objects_output2.txt")
	defer out.Close()
	files, _ := ioutil.ReadDir("/home/u/dev/telegram/japp/mirror/CommData1")
	sort.Slice(files, func(i, j int) bool {
		n1, _ := strconv.Atoi(strings.Split(files[i].Name(), "_")[0])
		n2, _ := strconv.Atoi(strings.Split(files[j].Name(), "_")[0])
		return n1 < n2
	})
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".bin") { continue }
		data, _ := ioutil.ReadFile(filepath.Join("/home/u/dev/telegram/japp/mirror/CommData1", f.Name()))
		if strings.Contains(f.Name(), "_received_") {
			fmt.Fprintf(out, "<-- %s \n", f.Name())
			data = data[1:]
		} else {
			fmt.Fprintf(out, "--> %s \n", f.Name())
		}
		buf := mtproto.NewDecodeBuf(data)
		buf.MySeekOffset(40); fmt.Fprintf(out, "MsgId: %d\n", buf.Long()); buf.MySeekOffset(8)
		for buf.GetOffset() < len(data) && buf.GetError() == nil {
			if obj := buf.Object(); obj != nil {
				objStr := obj.String()
				if !strings.Contains(objStr, "CRC32_ping_delay_disconnect") && !strings.Contains(objStr, "CRC32_pong") {
					// Use custom formatter with depth limit of 3
					formatted := formatObject(obj, 3)
					fmt.Fprintf(out, "Offset %d:\n%s\n", buf.GetOffset(), formatted)
					if invokeLayer, ok := obj.(*mtproto.TLInvokeWithLayer); ok {
						processQuery(invokeLayer.Query, out, "  ")
					}
				}
			} else { break }
		}
		fmt.Fprintln(out)
	}
}