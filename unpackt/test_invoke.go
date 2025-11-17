package main

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"reflect"

	"github.com/teamgram/proto/mtproto"
)

func main() {
	// Read one of the files with invokeWithLayer
	data, err := ioutil.ReadFile(filepath.Join("/home/u/dev/telegram/japp/mirror/CommData1", "01_sent_data.bin"))
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	
	buf := mtproto.NewDecodeBuf(data)
	buf.MySeekOffset(40)
	buf.Long() // MsgId
	buf.MySeekOffset(8)
	
	if obj := buf.Object(); obj != nil {
		objStr := fmt.Sprintf("%v", obj)
		fmt.Println("Object string:", objStr)
		fmt.Println("Object type:", reflect.TypeOf(obj))
		
		// Try to access fields using reflection
		v := reflect.ValueOf(obj)
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		
		if v.Kind() == reflect.Struct {
			t := v.Type()
			fmt.Println("\nNumber of fields:", v.NumField())
			for i := 0; i < v.NumField(); i++ {
				field := t.Field(i)
				value := v.Field(i)
				fmt.Printf("Field %d: Name=%s, Type=%v\n", i, field.Name, field.Type)
				
				// If it's Query field, try to parse it as an object
				if field.Name == "Query" {
					fmt.Println("Found Query field!")
					// Check if it's a TLObject
					if queryObj, ok := value.Interface().(mtproto.TLObject); ok {
						fmt.Printf("Query is TLObject: %v\n", queryObj)
					} else if queryBytes, ok := value.Interface().([]byte); ok {
						fmt.Printf("Query is bytes, length: %d\n", len(queryBytes))
						// Try to decode the query bytes
						queryBuf := mtproto.NewDecodeBuf(queryBytes)
						if queryObj := queryBuf.Object(); queryObj != nil {
							fmt.Printf("Decoded query object: %v\n", queryObj)
						}
					} else {
						fmt.Printf("Query type: %T, value: %v\n", value.Interface(), value.Interface())
					}
				}
			}
		}
	}
}