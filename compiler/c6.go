package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/teamgram/proto/mtproto"
)

var out string

func processTLBytes(data []byte) string {
	var o1 string
	dBuf := mtproto.NewDecodeBuf(data)
	dBuf.MySeekOffset(40)
	dBuf.Long()
	dBuf.MySeekOffset(8)
	for dBuf.GetOffset() < len(data) {
		obj := dBuf.Object()
		dBuf.GetOffset()
		if obj == nil {
			break
		}
	
		o1 = fmt.Sprintf("   result := %# v\n", Formatter(obj))
		o1 += fmt.Sprintln(`
    buf := mtproto.NewEncodeBuf(512)
    result.Encode(buf, 158)
    cp.send(buf.GetBuf(), salt, sessionId)`)
	}
	return o1
}

func getT(data []byte) mtproto.TLObject {
	dBuf := mtproto.NewDecodeBuf(data)
	dBuf.MySeekOffset(40)
	dBuf.Long()
	dBuf.MySeekOffset(8)
	for dBuf.GetOffset() < len(data) {
		obj := dBuf.Object()
		dBuf.GetOffset()
		if obj == nil {
			break
		}
		return obj
	}
	return nil
}

func readBytes(fullPath string) []byte {
	data, _ := ioutil.ReadFile(fullPath)
	
	if strings.Contains(filepath.Base(fullPath), "_received_") && len(data) > 1 {
		data = data[1:]
	}
	return data
}

func insertAtLine(filename string, lineNum int, content string) error {
	data, _ := ioutil.ReadFile(filename)
	lines := strings.Split(string(data), "\n")
	lines = append(lines[:lineNum-1], append([]string{content}, lines[lineNum-1:]...)...)
	return ioutil.WriteFile(filename, []byte(strings.Join(lines, "\n")), 0644)
}

func main() {
	// fullPath := "/home/u/dev/telegram/japp/mirror/CommData-send2u2/268_received_data.bin"
	// fullPath := "/home/u/dev/telegram/japp/mirror/CommData-send2u2/270_received_data.bin"
	// fullPath := "/home/u/dev/telegram/japp/mirror/CommData-send2u2/273_received_data.bin"
	
	// fullPathIn := "/home/u/dev/telegram/japp/mirror/CommData-send2u2/267_sent_data.bin"
	fullPathIn := "/home/u/dev/telegram/japp/mirror/CommData-send2u2/" + os.Args[1]
	dataIn := readBytes(fullPathIn)
	// fullPathOut := "/home/u/dev/telegram/japp/mirror/CommData-send2u2/268_received_data.bin"
	fullPathOut := "/home/u/dev/telegram/japp/mirror/CommData-send2u2/" + os.Args[2]
	dataOut := readBytes(fullPathOut)
	line := 26
	out = fmt.Sprintf("\tcase %T:\n%s", getT(dataIn), processTLBytes(dataOut))	
	fmt.Println(out)
	
	err := insertAtLine("dummy.go", line, out)
	if err != nil {
		fmt.Printf("Error inserting content: %v\n", err)
	} else {
		fmt.Printf("Successfully inserted content at line %d in dummy.go\n", line)
	}
}