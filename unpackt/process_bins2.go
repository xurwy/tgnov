package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/kr/pretty"
	"github.com/teamgram/proto/mtproto"
)

func processTLBytes(filename string, data []byte) {
	fmt.Printf("\n\n========================================")
	fmt.Printf("\n=== Processing: %s ===\n", filename)
	fmt.Printf("========================================\n")

	// Determine offset based on file type
	offset := 40
	if strings.HasSuffix(filename, "_received_data.bin") {
		offset = 41
	}

	dBuf := mtproto.NewDecodeBuf(data)
	dBuf.MySeekOffset(offset)
	msgId := dBuf.Long()
	dBuf.MySeekOffset(8)

	foundAny := false
	for dBuf.GetOffset() < len(data) {
		obj := dBuf.Object()
		if obj == nil {
			break
		}
		foundAny = true
		fmt.Printf("\n   MsgId: %d\n", msgId)
		fmt.Printf("   Result: %# v\n", pretty.Formatter(obj))
	}

	// If no objects found using normal way, use scanning method
	if !foundAny {
		fmt.Printf("\n   No objects found with normal parsing, trying scan method...\n")
		findObjectsInBytes(data, filename)
	}
}

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
			// Skip TLMsgContainer objects
			if _, ok := obj.(*mtproto.TLMsgContainer); ok {
				continue
			}

			foundAny = true
			fmt.Printf("\n>>> Found object at offset %d\n", offset)

			// Try to extract msgId if there's enough data before this offset
			if offset >= 8 {
				msgBuf := mtproto.NewDecodeBuf(data[offset-8:])
				msgId := msgBuf.Long()
				fmt.Printf("    Potential MsgId (8 bytes before): %d\n", msgId)
			}

			fmt.Printf("%# v\n", pretty.Formatter(obj))

			// Stop after finding the first valid object
			break
		}
	}

	if !foundAny {
		fmt.Printf("    No valid objects found\n")
	}
}


func main() {
	// Increase memory limit and disable GC pressure
	debug.SetGCPercent(200)
	debug.SetMemoryLimit(2 << 30) // 2GB memory limit

	// Get directory path from command line argument, default to current directory
	dirPath := "."
	if len(os.Args) > 1 {
		dirPath = os.Args[1]
	}

	fmt.Printf("Processing .bin files in directory: %s\n\n", dirPath)

	// Read all .bin files in specified directory
	pattern := filepath.Join(dirPath, "*.bin")
	files, err := filepath.Glob(pattern)
	if err != nil {
		fmt.Printf("Error reading files: %v\n", err)
		return
	}

	if len(files) == 0 {
		fmt.Printf("No .bin files found in %s\n", dirPath)
		return
	}

	fmt.Printf("Found %d .bin files\n", len(files))


	// Then process *_sent_data.bin and *_received_data.bin files
	fmt.Println("\n\n==============================================")
	fmt.Println("===  PROCESSING SENT/RECEIVED DATA FILES  ===")
	fmt.Println("==============================================")

	for _, filename := range files {
		base := filepath.Base(filename)
		if strings.HasSuffix(base, "_sent_data.bin") || strings.HasSuffix(base, "_received_data.bin") {
			data, err := os.ReadFile(filename)
			if err != nil {
				fmt.Printf("Error reading %s: %v\n", filename, err)
				continue
			}
			processTLBytes(filename, data)

			// Free memory after each file
			data = nil
			runtime.GC()
		}
	}

	fmt.Println("\n\n==============================================")
	fmt.Println("===  PROCESSING COMPLETE  ===")
	fmt.Println("==============================================")
}
