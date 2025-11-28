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

		fmt.Printf("\n   result := %# v\n", pretty.Formatter(obj))
	}
}

func findObjectsInBytes(filename string, data []byte) {
	fmt.Printf("\n\n========================================")
	fmt.Printf("\n=== Scanning %s (%d bytes) ===\n", filename, len(data))
	fmt.Printf("========================================\n")

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

	// Process buff_*.bin files first
	fmt.Println("==============================================")
	fmt.Println("===  PROCESSING BUFF FILES FIRST  ===")
	fmt.Println("==============================================")

	for _, filename := range files {
		if strings.HasPrefix(filepath.Base(filename), "buff_") {
			data, err := os.ReadFile(filename)
			if err != nil {
				fmt.Printf("Error reading %s: %v\n", filename, err)
				continue
			}
			findObjectsInBytes(filename, data)

			// Free memory after each file
			data = nil
			runtime.GC()
		}
	}

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
