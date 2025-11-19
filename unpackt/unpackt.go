package main

import (
	"fmt"
	"io/ioutil"

	"github.com/kr/pretty"
	"github.com/teamgram/proto/mtproto"
)

// findObjectsInBytes tries to decode objects from byte data at different offsets
func findObjectsInBytes(data []byte, label string) {
	fmt.Printf("\n=== Scanning %s (%d bytes) ===\n", label, len(data))
	
	foundAny := false
	for offset := 0; offset < len(data)-4; offset++ {
		// Skip if remaining data is too small
		if len(data[offset:]) < 8 {
			continue
		}
		
		// Create a decode buffer from the current offset
		dBuf := mtproto.NewDecodeBuf(data[offset:])
		
		// Try to decode an object
		obj := dBuf.Object()
		
		if obj != nil {
			foundAny = true
			fmt.Printf("\n>>> Found object at offset %d\n", offset)
			fmt.Printf("    Type: %T\n", obj)
			fmt.Printf("%# v\n", pretty.Formatter(obj))
			
			// If it's TLInvokeWithLayer, try to decode its query
			if invokeLayer, ok := obj.(*mtproto.TLInvokeWithLayer); ok {
				fmt.Printf("\n    TLInvokeWithLayer detected!\n")
				if invokeLayer.Query != nil {
					// Recursively decode the query bytes
					findObjectsInBytes(invokeLayer.Query, "InvokeWithLayer.Query")
				}
			}
			
			// Also try to decode as a message with msgId and seqNo
			if len(data[offset:]) >= 16 {
				dBuf2 := mtproto.NewDecodeBuf(data[offset:])
				msgId := dBuf2.Long()
				seqNo := dBuf2.Int()
				msgObj := dBuf2.Object()
				if msgObj != nil {
					fmt.Printf("\n    As message structure:\n")
					fmt.Printf("    MsgId: %d, SeqNo: %d\n", msgId, seqNo)
					fmt.Printf("    Message object type: %T\n", msgObj)
				}
			}
		}
	}
	
	if !foundAny {
		fmt.Printf("    No valid objects found\n")
	}
}

func main() {
    // Read the binary file
    data, err := ioutil.ReadFile("/home/u/dev/telegram/japp/mirror/CommData1/50_sent_data.bin")
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("File size: %d bytes\n", len(data))
    
    // Use the abstracted function to find objects
    findObjectsInBytes(data, "Main file")
    
//     fmt.Println("\n=== Trying with standard message structure ===")
//     // Try unpacking as standard message from start
//     if len(data) >= 16 {
//         unpackMessage(data)
//     }
}

func unpackMessage(data []byte) {
    dBuf := mtproto.NewDecodeBuf(data)
    msgId := dBuf.Long()
    seqNo := dBuf.Int()
    obj := dBuf.Object()
    
    fmt.Printf("MsgId: %d, SeqNo: %d\n", msgId, seqNo)
    fmt.Printf("Object: %# v\n", pretty.Formatter(obj))
}

func main2() {
	data, err := ioutil.ReadFile("/home/u/dev/telegram/japp/mirror/CommData1/14_received_data.bin")
	fmt.Println("datafile len", len(data))
	if err != nil {
		panic(err)
	}
	// 40-48 = msgId  
	// 48-52 = invokewithlayer
	// 52-56 = booltrue
	// 56-60 = initconnection
	// 48 = invokewithlayer, 56 = initconnection
	dBuf0 := mtproto.NewDecodeBuf(data)
	dBuf0.MySeekOffset(40)
	msgId := dBuf0.Long()
	fmt.Printf("msgId %d\n", msgId)
	// 7571067084324932608
	// 7571067084324932608

	offset := 56
	dBuf := mtproto.NewDecodeBuf(data[offset:])
	authKeyId := dBuf.Long()
	currentPos := dBuf.GetOffset()
	
	obj := dBuf.Object()
	
	fmt.Printf("%d Pos %d->%d | AuthKeyId: %x\n", offset, currentPos, dBuf.GetOffset(), authKeyId)
	if obj != nil {
		fmt.Printf("%# v\n", pretty.Formatter(obj))
		currentPos = dBuf.GetOffset()
		initConn := obj.(*mtproto.TLInitConnection)
		dBuf2 := mtproto.NewDecodeBuf(initConn.Query)
		fmt.Printf("%d dbuf2 %# v\n", currentPos, pretty.Formatter(dBuf2.Object()))
	} else if dBuf.GetError() != nil {
		fmt.Printf("Error: %v\n", dBuf.GetError())
		if currentPos+8+4 <= len(data) {
			constructorBytes := data[currentPos+8 : currentPos+8+4]
			fmt.Printf("Constructor bytes at pos %d: %x\n", currentPos+8, constructorBytes)
		}
	}
}
