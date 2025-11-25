package main

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/teamgram/proto/mtproto"
	cpretty "github.com/xurwy/mpretty"
)


func processTLBytes(data []byte) {
	dBuf := mtproto.NewDecodeBuf(data)
	dBuf.MySeekOffset(40)
	msgId := dBuf.Long()
	
	fmt.Println("package main")
	fmt.Println()
	fmt.Println("import (")
	fmt.Println("\t\"fmt\"")
	fmt.Println("\t\"github.com/teamgram/proto/mtproto\"")
	fmt.Println("\t\"google.golang.org/protobuf/types/known/wrapperspb\"")
	fmt.Println(")")
	fmt.Println()
	fmt.Println("func main() {")
	fmt.Printf("\t// MsgId: %d\n", msgId)
	
	dBuf.MySeekOffset(8)
	varNum := 1
	for dBuf.GetOffset() < len(data) {
		obj := dBuf.Object()
		if obj == nil {
			break
		}
		
		// Handle special case for TLContactsImportedContacts
		if tlContacts, ok := obj.(*mtproto.TLContactsImportedContacts); ok && tlContacts.Data2 != nil {
			fmt.Printf("\tobj%d := &mtproto.TLContactsImportedContacts{\n", varNum)
			fmt.Printf("\t\tData2: &mtproto.Contacts_ImportedContacts%# v,\n", GoFormatterNoType(tlContacts.Data2))
			fmt.Printf("\t}\n")
		} else if tlResult, ok := obj.(*mtproto.TLRpcResult); ok {
			fmt.Printf("\tobj%d := &mtproto.TLRpcResult{\n", varNum)
			fmt.Printf("\t\tReqMsgId:\t%d,\n", tlResult.ReqMsgId)
			if tlResult.Result != nil {
				if innerContacts, ok := tlResult.Result.(*mtproto.TLContactsImportedContacts); ok && innerContacts.Data2 != nil {
					fmt.Printf("\t\tResult:\t&mtproto.TLContactsImportedContacts{\n")
					fmt.Printf("\t\t\tData2: &mtproto.Contacts_ImportedContacts%# v,\n", GoFormatterNoType(innerContacts.Data2))
					fmt.Printf("\t\t},\n")
				} else {
					fmt.Printf("\t\tResult:\t%# v,\n", GoFormatter(tlResult.Result))
				}
			}
			fmt.Printf("\t},\n")
		} else {
			fmt.Printf("\tobj%d := %# v\n", varNum, GoFormatter(obj))
		}
		fmt.Printf("\tfmt.Printf(\"%%#v\\n\", obj%d)\n", varNum)
		fmt.Println()
		varNum++
	}
	
	fmt.Println("}")
}

func main() {
	// Set to true to use cpretty formatter for debugging
	// Set to false to generate compilable Go code
	usePrettyDebug := false

	fullPath := "/home/u/dev/telegram/japp/mirror/CommData-send2u2/268_received_data.bin"
	data2, _ := ioutil.ReadFile(fullPath)
	fmt.Println("// datafile len", len(data2))
	if strings.Contains(filepath.Base(fullPath), "_received_") && len(data2) > 1 {
		data2 = data2[1:]
	}
	
	if usePrettyDebug {
		processTLBytesDebug(data2)
	} else {
		processTLBytes(data2)
	}
}

func processTLBytesDebug(data []byte) {
	dBuf := mtproto.NewDecodeBuf(data)
	dBuf.MySeekOffset(40)
	msgId := dBuf.Long()
	fmt.Printf("MsgId: %d\n", msgId)

	dBuf.MySeekOffset(8)
	for dBuf.GetOffset() < len(data) {
		obj := dBuf.Object()
		offset := dBuf.GetOffset()
		if obj == nil {
			break
		}
		fmt.Printf("Offset %d: %# v\n", offset, cpretty.Formatter(obj))
	}
	fmt.Println()
}