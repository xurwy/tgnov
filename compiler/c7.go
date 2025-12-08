package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
	
		o1 = fmt.Sprintf("\n   result := %# v\n", Formatter(obj))
		o1 += fmt.Sprintln(`
    buf := mtproto.NewEncodeBuf(512)
    result.Encode(buf, 158)
    cp.send(buf.GetBuf(), salt, sessionId)
	
	`)
	}

    re := regexp.MustCompile(`ReqMsgId:\s+\d+`)
    o1 = re.ReplaceAllString(o1, "ReqMsgId: msgId")

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

func findTLInOut1(tlType string) (string, string, string) {
	// Read out1.txt
	data, err := ioutil.ReadFile("out1.txt")
	if err != nil {
		fmt.Printf("Error reading out1.txt: %v\n", err)
		return "", "", ""
	}
	
	lines := strings.Split(string(data), "\n")
	
	// Find the line containing the TL type
	for i, line := range lines {
		if strings.Contains(line, tlType) {
			// Look backwards to find the Processing line
			for j := i; j >= 0 && j > i-10; j-- {
				if strings.Contains(lines[j], "Processing") && strings.Contains(lines[j], "_sent_data.bin") {
					re := regexp.MustCompile(`Processing (\d+)_sent_data\.bin`)
					matches := re.FindStringSubmatch(lines[j])
					if len(matches) > 1 {
						sentNum, _ := strconv.Atoi(matches[1])
						receiveNum := sentNum + 1
						
						sentFile := fmt.Sprintf("%d_sent_data.bin", sentNum)
						receiveFile := fmt.Sprintf("%d_received_data.bin", receiveNum)
						
						return sentFile, receiveFile, ""
					}
				}
			}
		}
	}
	return "", "", ""
}

func main() {
	if len(os.Args) > 1 {
		// Original functionality with command line arguments
		fullPathIn := "/home/u/dev/telegram/japp/mirror/CommData1/" + os.Args[1]
		dataIn := readBytes(fullPathIn)
		fullPathOut := "/home/u/dev/telegram/japp/mirror/CommData1/" + os.Args[2]
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
	} else {
		// New functionality: search for not found TLs
		notFoundFile, err := os.Open("./not_found_tl.txt")
		if err != nil {
			fmt.Printf("Error opening not_found_tl.txt: %v\n", err)
			return
		}
		defer notFoundFile.Close()
		
		scanner := bufio.NewScanner(notFoundFile)
		processed := make(map[string]bool)
		var allCases []string
		
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "Not found") {
				// Extract the TL type name
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					tlType := parts[2]
					// Remove the *mtproto. prefix if present
					tlType = strings.TrimPrefix(tlType, "*mtproto.")
					
					if processed[tlType] {
						continue
					}
					processed[tlType] = true
					
					sentFile, receiveFile, _ := findTLInOut1(tlType)
					fmt.Println(sentFile, receiveFile)
					if sentFile != "" && receiveFile != "" {
						// Read the actual binary files to process them
						fullPathIn := "/home/u/dev/telegram/japp/mirror/CommData-send2u22/" + sentFile
						dataIn := readBytes(fullPathIn)
						fullPathOut := "/home/u/dev/telegram/japp/mirror/CommData-send2u22/" + receiveFile
						dataOut := readBytes(fullPathOut)
						
						if len(dataIn) > 0 && len(dataOut) > 0 {
							caseStr := fmt.Sprintf("\tcase %T:\n%s", getT(dataIn), processTLBytes(dataOut))
							allCases = append(allCases, caseStr)
							fmt.Printf("Generated case for %s\n", tlType)
						}
					}
				}
			}
		}
		
		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading not_found_tl.txt: %v\n", err)
		}
		
		// Output all cases and insert them into dummy.go
		if len(allCases) > 0 {
			line := 26
			for _, caseStr := range allCases {
				fmt.Println(caseStr)
				err := insertAtLine("dummy.go", line, caseStr)
				if err != nil {
					fmt.Printf("Error inserting content: %v\n", err)
				} else {
					fmt.Printf("Successfully inserted content at line %d in dummy.go\n", line)
					// line++ // Increment for next insertion
				}
			}
		}
	}
}

/*
Update @c7.go to search not found tl @not_found_tl.txt in out1.txt and output tl according to its reply. Usually the next file is a reply for an arbitrary object. For example TLMessagesGetSearchCounters is at 278_sent_data.bin and the reply is 279_received_data.bin.
*/