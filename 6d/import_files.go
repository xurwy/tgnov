// +build ignore

package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// ImportFileData imports file data from getfile_data_pairs.txt into MongoDB
func ImportFileData(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer for long lines

	var documentID int64
	var documentData []byte
	seen := make(map[int64]bool) // Track seen document IDs to handle duplicates

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Check for document ID line
		if strings.HasPrefix(line, "  Document Id:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				idStr := strings.TrimSpace(parts[1])
				id, err := strconv.ParseInt(idStr, 10, 64)
				if err != nil {
					log.Printf("Warning: Failed to parse document ID on line %d: %v", lineNum, err)
					continue
				}
				documentID = id
			}
		}

		// Check for bytes line
		if strings.HasPrefix(line, "  Bytes:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				hexStr := strings.TrimSpace(parts[1])

				// Pad odd-length hex strings with a trailing 0
				if len(hexStr)%2 != 0 {
					hexStr = hexStr + "0"
					log.Printf("Warning: Padded odd-length hex data on line %d (document ID: %d)", lineNum, documentID)
				}

				data, err := hex.DecodeString(hexStr)
				if err != nil {
					log.Printf("Warning: Failed to decode hex data on line %d: %v", lineNum, err)
					continue
				}
				documentData = data

				// Save to MongoDB if we have both ID and data, and haven't seen this ID before
				if documentID != 0 && len(documentData) > 0 {
					if seen[documentID] {
						log.Printf("Skipping duplicate document ID: %d", documentID)
					} else {
						err := SaveFileData(documentID, documentData)
						if err != nil {
							log.Printf("Warning: Failed to save document ID %d: %v", documentID, err)
						} else {
							log.Printf("Saved document ID: %d (%d bytes)", documentID, len(documentData))
							seen[documentID] = true
						}
					}

					// Reset for next pair
					documentID = 0
					documentData = nil
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	log.Printf("Import complete. Imported %d unique documents", len(seen))
	return nil
}

func main() {
	mongoURL := flag.String("mongo", "mongodb://localhost:27017/telegram", "MongoDB connection URL")
	filename := flag.String("file", "getfile_data_pairs.txt", "File to import")
	flag.Parse()

	// Initialize MongoDB
	if err := InitMongoDB(*mongoURL); err != nil {
		log.Fatalf("Failed to initialize MongoDB: %v", err)
	}
	defer CloseMongoDB()

	// Import file data
	log.Printf("Importing file data from %s...", *filename)
	if err := ImportFileData(*filename); err != nil {
		log.Fatalf("Failed to import file data: %v", err)
	}

	log.Println("Import completed successfully!")
}