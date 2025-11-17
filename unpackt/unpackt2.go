package main

import (
	"fmt"
	"io/ioutil"

	"github.com/kr/pretty"
	"github.com/teamgram/proto/mtproto"
)

func bytesToTL2(b []byte) *mtproto.TLMessage2 {
	msg := &mtproto.TLMessage2{}
	msg.Decode(mtproto.NewDecodeBuf(b))
	return msg
}

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
			// dBuf.MySeekOffset(1)
			// fmt.Printf("%d ", offset)
			break
		}
		fmt.Printf("Offset %d: %# v\n", offset, pretty.Formatter(obj))
	}
	fmt.Println()
}

func processTLBytesReceived(data []byte) {
	dBuf := mtproto.NewDecodeBuf(data)
	
	dBuf.MySeekOffset(41)
	msgId := dBuf.Long()
	// dBuf.Int()
	
	fmt.Printf("MsgId: %d\n", msgId)
	dBuf.MySeekOffset(8)
	for dBuf.GetOffset() < len(data) && dBuf.GetError() == nil {
		offset := dBuf.GetOffset()
		obj := dBuf.Object()
		if obj == nil {
			break
		}
		fmt.Printf("Offset %d: %# v\n", offset, pretty.Formatter(obj))
	}
}

func main() {
	data, err := ioutil.ReadFile("/home/u/dev/telegram/japp/mirror/CommData1/040_sent_data.bin")
	// res := bytesToTL2(data[16:])
	fmt.Println("datafile len", len(data))
	data2, err := ioutil.ReadFile("/home/u/dev/telegram/japp/mirror/CommData1/069_received_data.bin")
	// fmt.Printf("Res %# v\n", pretty.Formatter(res.Object))
	fmt.Println("datafile len", len(data2))
	if err != nil {
		panic(err)
	}
	processTLBytes(data)
	fmt.Println("processTLBytesReceived\n")
	processTLBytes(data2[1:])
	processTLBytesReceived(data2)
}
