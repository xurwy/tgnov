package main

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/teamgram/proto/mtproto"
)

// 267_sent_data.bin (len=216)
// 268_received_data.bin (len=184)

func processTLBytes(data []byte) {
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
		fmt.Printf("Offset %d: %+v\n", offset, obj)
	}
	fmt.Println()
}

func processBinFiles(folderPath string) {
	files, _ := filepath.Glob(filepath.Join(folderPath, "*.bin"))
	for _, fullPath := range files {
		data, _ := ioutil.ReadFile(fullPath)
		if strings.Contains(filepath.Base(fullPath), "_received_") && len(data) > 1 {
			data = data[1:]
		}
		fmt.Printf("Processing %s (len=%d)\n", filepath.Base(fullPath), len(data))
		processTLBytes(data)
	}
}

func generate(){
	data, _ := ioutil.ReadFile("/home/u/dev/telegram/japp/mirror/CommData-send2u2/267_sent_data.bin") // valid
	processTLBytes(data)
}

func main() {
	// processBinFiles("/home/u/dev/telegram/japp/mirror/CommData-send2u2/")
	generate()
}