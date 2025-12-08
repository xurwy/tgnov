// +build ignore

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// DocumentMapping stores the mapping between document ID and its binary file
type DocumentMapping struct {
	DocumentID      int64
	SentMsgId       int64
	SentFile        string
	ReceivedMsgId   int64
	ReceivedFile    string
	Offset          int
}

func main() {
	inputFile := flag.String("input", "/home/u/dev/telegram2/tgnov/unpackt/all2.txt", "Input file path")
	outputFile := flag.String("output", "document_mappings.txt", "Output file path")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Parsing file: %s", *inputFile)

	// Open input file
	file, err := os.Open(*inputFile)
	if err != nil {
		log.Fatalf("Failed to open input file: %v", err)
	}
	defer file.Close()

	// Regular expressions
	processingRegex := regexp.MustCompile(`=== Processing: (.+) ===`)
	msgIdRegex := regexp.MustCompile(`^\s*MsgId:\s+(\d+)`)
	reqMsgIdRegex := regexp.MustCompile(`^\s*ReqMsgId:\s+(\d+)`)
	docIdRegex := regexp.MustCompile(`^\s*Id:\s+(\d+)`)
	offsetRegex := regexp.MustCompile(`>>> Found object at offset (\d+)`)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 10MB buffer

	// Data structures
	type SentRequest struct {
		MsgId      int64
		File       string
		DocumentID int64
	}

	type ReceivedResponse struct {
		ReqMsgId int64
		File     string
		Offset   int
	}

	sentRequests := make(map[int64]*SentRequest)        // msgId -> SentRequest
	receivedResponses := make(map[int64]*ReceivedResponse) // reqMsgId -> ReceivedResponse

	var (
		currentFile      string
		currentMsgId     int64
		currentReqMsgId  int64
		currentDocId     int64
		currentOffset    int
		inSentData       bool
		inReceivedData   bool
		foundReqMsgId    bool
	)

	lineNum := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		// Check for new file being processed
		if matches := processingRegex.FindStringSubmatch(line); matches != nil {
			// Reset state for new file
			currentFile = matches[1]
			currentMsgId = 0
			currentReqMsgId = 0
			currentDocId = 0
			currentOffset = 0
			foundReqMsgId = false

			// Determine if this is sent or received data
			inSentData = strings.Contains(currentFile, "_sent_data.bin")
			inReceivedData = strings.Contains(currentFile, "_received_data.bin")

			continue
		}

		// Check for offset in received data (scan method)
		if inReceivedData {
			if matches := offsetRegex.FindStringSubmatch(line); matches != nil {
				currentOffset, _ = strconv.Atoi(matches[1])
			}
		}

		// Extract MsgId (in sent data)
		if inSentData {
			if matches := msgIdRegex.FindStringSubmatch(line); matches != nil {
				currentMsgId, _ = strconv.ParseInt(matches[1], 10, 64)
			}
		}

		// Extract ReqMsgId (in received data)
		if inReceivedData {
			if matches := reqMsgIdRegex.FindStringSubmatch(line); matches != nil {
				currentReqMsgId, _ = strconv.ParseInt(matches[1], 10, 64)
				foundReqMsgId = true
			}
		}

		// Extract document ID (in sent data, after MsgId)
		if inSentData && currentMsgId != 0 {
			if matches := docIdRegex.FindStringSubmatch(line); matches != nil {
				docId, _ := strconv.ParseInt(matches[1], 10, 64)
				// Only consider document IDs that look like sticker IDs (large numbers)
				if docId > 1000000000000000000 {
					currentDocId = docId

					// Store sent request
					sentRequests[currentMsgId] = &SentRequest{
						MsgId:      currentMsgId,
						File:       currentFile,
						DocumentID: currentDocId,
					}

					log.Printf("Found sent request: MsgId=%d, DocId=%d, File=%s",
						currentMsgId, currentDocId, currentFile)

					// Reset for next request in same file
					currentMsgId = 0
					currentDocId = 0
				}
			}
		}

		// Store received response when we have ReqMsgId
		if inReceivedData && foundReqMsgId && currentReqMsgId != 0 {
			// Check if this is a TLUploadFile response (contains file bytes)
			if strings.Contains(line, "TLUploadFile") {
				receivedResponses[currentReqMsgId] = &ReceivedResponse{
					ReqMsgId: currentReqMsgId,
					File:     currentFile,
					Offset:   currentOffset,
				}

				log.Printf("Found received response: ReqMsgId=%d, File=%s, Offset=%d",
					currentReqMsgId, currentFile, currentOffset)

				// Reset
				currentReqMsgId = 0
				currentOffset = 0
				foundReqMsgId = false
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Scanner error: %v", err)
	}

	// Match sent requests with received responses
	var mappings []DocumentMapping
	for msgId, sent := range sentRequests {
		if received, ok := receivedResponses[msgId]; ok {
			mapping := DocumentMapping{
				DocumentID:    sent.DocumentID,
				SentMsgId:     sent.MsgId,
				SentFile:      sent.File,
				ReceivedMsgId: received.ReqMsgId,
				ReceivedFile:  received.File,
				Offset:        received.Offset,
			}
			mappings = append(mappings, mapping)
		}
	}

	// Write output
	out, err := os.Create(*outputFile)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer out.Close()

	writer := bufio.NewWriter(out)
	fmt.Fprintf(writer, "# Document ID mappings (document_id, sent_msgid, sent_file, received_msgid, received_file, offset)\n")
	for _, m := range mappings {
		fmt.Fprintf(writer, "%d,%d,%s,%d,%s,%d\n",
			m.DocumentID, m.SentMsgId, m.SentFile, m.ReceivedMsgId, m.ReceivedFile, m.Offset)
	}
	writer.Flush()

	// Summary
	log.Println(strings.Repeat("=", 60))
	log.Println("PARSING SUMMARY")
	log.Println(strings.Repeat("=", 60))
	log.Printf("Total sent requests found:      %d", len(sentRequests))
	log.Printf("Total received responses found: %d", len(receivedResponses))
	log.Printf("Total matched mappings:         %d", len(mappings))
	log.Printf("Output written to:              %s", *outputFile)
	log.Println(strings.Repeat("=", 60))
}
