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
					// fmt.Fprintf(out, "Offset %d: %s\n", buf.GetOffset(), objStr)
					fmt.Fprintf(out, "Offset %d: %+v\n", buf.GetOffset(), obj)
					if invokeLayer, ok := obj.(*mtproto.TLInvokeWithLayer); ok {
						processQuery(invokeLayer.Query, out, "  ")
					}
				}
			} else { break }
		}
		fmt.Fprintln(out)
	}
}
