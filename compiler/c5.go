package main

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/teamgram/proto/mtproto"
)

func processTLBytes(data []byte) {
	dBuf := mtproto.NewDecodeBuf(data)
	dBuf.MySeekOffset(40)
	msgId := dBuf.Long()
	fmt.Printf("// MsgId: %d\n", msgId)
	dBuf.MySeekOffset(8)
	for dBuf.GetOffset() < len(data) {
		obj := dBuf.Object()
		dBuf.GetOffset()
		if obj == nil {
			break
		}
		fmt.Println("func main() {")
		fmt.Printf("\tresult := %# v\n", Formatter(obj))
		fmt.Println()
		fmt.Println("\tfmt.Printf(\"Object loaded successfully: %T\\n\", result)")
		fmt.Println("\tfmt.Printf(\"Object content: %+v\\n\", result)")
		fmt.Println("}")
	}
}

func main() {
	fullPath := "/home/u/dev/telegram/japp/mirror/CommData-send2u2/268_received_data.bin"
	// fullPath := "/home/u/dev/telegram/japp/mirror/CommData-send2u2/270_received_data.bin"
	// fullPath := "/home/u/dev/telegram/japp/mirror/CommData-send2u2/273_received_data.bin"
	data, _ := ioutil.ReadFile(fullPath)
	
	// Generate Go package header
	fmt.Println("package main")
	fmt.Println()
	fmt.Println("import (")
	fmt.Println("\t\"fmt\"")
	fmt.Println()
	fmt.Println("\t\"github.com/teamgram/proto/mtproto\"")
	fmt.Println()
	fmt.Println("\t\"google.golang.org/protobuf/types/known/wrapperspb\"")
	fmt.Println(")")
	fmt.Println()
	fmt.Printf("// datafile len %d\n", len(data))
	
	if strings.Contains(filepath.Base(fullPath), "_received_") && len(data) > 1 {
		data = data[1:]
	}
	processTLBytes(data)
}