// +build ignore

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// FileDataDoc stores file data for upload.getFile responses
type FileDataDoc struct {
	DocumentID int64     `bson:"document_id"`
	Data       []byte    `bson:"data"`
	CreatedAt  time.Time `bson:"created_at"`
	UpdatedAt  time.Time `bson:"updated_at"`
}

func main() {
	mongoURL := flag.String("mongo", "mongodb://localhost:27017/telegram", "MongoDB connection URL")
	inputFile := flag.String("input", "sticker_set.txt", "Input file with sticker data")
	dryRun := flag.Bool("dry-run", false, "Don't actually insert, just report")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(*mongoURL))
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	defer client.Disconnect(context.Background())

	// Ping to verify connection
	if err := client.Ping(ctx, nil); err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}

	db := client.Database("telegram")
	collection := db.Collection("file_data")

	log.Printf("Connected to MongoDB: %s", *mongoURL)
	log.Printf("Dry run mode: %v", *dryRun)
	log.Printf("Parsing file: %s", *inputFile)

	// Open input file
	file, err := os.Open(*inputFile)
	if err != nil {
		log.Fatalf("Failed to open input file: %v", err)
	}
	defer file.Close()

	// Regular expressions
	idRegex := regexp.MustCompile(`^\s*Id:\s+(\d+),`)
	size2Regex := regexp.MustCompile(`^\s*Size2_INT64:\s+(\d+),`)
	bytesRegex := regexp.MustCompile(`^\s*Bytes:\s+\{(0x[0-9a-fA-F]+(?:,\s*0x[0-9a-fA-F]+)*)\}`)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 10MB buffer for long lines

	var (
		currentDocID  int64
		currentSize   int64
		totalDocs     int
		insertedDocs  int
		skippedDocs   int
		inDocument    bool
	)

	for scanner.Scan() {
		line := scanner.Text()

		// Check if we're starting a document block
		if strings.Contains(line, `PredicateName: "document"`) {
			inDocument = true
			currentDocID = 0
			currentSize = 0
			continue
		}

		if !inDocument {
			continue
		}

		// Extract document ID
		if matches := idRegex.FindStringSubmatch(line); matches != nil {
			currentDocID, _ = strconv.ParseInt(matches[1], 10, 64)
			continue
		}

		// Extract size
		if matches := size2Regex.FindStringSubmatch(line); matches != nil {
			currentSize, _ = strconv.ParseInt(matches[1], 10, 64)
			continue
		}

		// Extract bytes
		if matches := bytesRegex.FindStringSubmatch(line); matches != nil {
			if currentDocID == 0 {
				log.Printf("Warning: Found bytes without document ID")
				continue
			}

			// Parse hex bytes
			hexBytes := strings.Split(matches[1], ",")
			var data []byte
			for _, hexByte := range hexBytes {
				hexByte = strings.TrimSpace(hexByte)
				// Remove 0x prefix
				hexByte = strings.TrimPrefix(hexByte, "0x")
				val, err := strconv.ParseUint(hexByte, 16, 8)
				if err != nil {
					log.Printf("Failed to parse hex byte %s: %v", hexByte, err)
					continue
				}
				data = append(data, byte(val))
			}

			totalDocs++

			// This is thumbnail data, not the actual file
			// We need to create a valid gzipped TGS file
			// TGS files are gzipped JSON (Lottie animation format)
			// For now, we'll create a minimal valid gzipped placeholder
			gzipData, err := createGzippedPlaceholder(currentDocID)
			if err != nil {
				log.Printf("Failed to create gzip data for doc %d: %v", currentDocID, err)
				skippedDocs++
				inDocument = false
				continue
			}

			log.Printf("Document %d: thumbnail size=%d bytes, creating gzipped file size=%d bytes (original size=%d)",
				currentDocID, len(data), len(gzipData), currentSize)

			// Insert into database
			if !*dryRun {
				doc := FileDataDoc{
					DocumentID: currentDocID,
					Data:       gzipData,
					CreatedAt:  time.Now(),
					UpdatedAt:  time.Now(),
				}

				// Upsert (update if exists, insert if not)
				filter := bson.M{"document_id": currentDocID}
				update := bson.M{
					"$set": bson.M{
						"document_id": doc.DocumentID,
						"data":        doc.Data,
						"updated_at":  doc.UpdatedAt,
					},
					"$setOnInsert": bson.M{
						"created_at": doc.CreatedAt,
					},
				}
				opts := options.Update().SetUpsert(true)

				_, err := collection.UpdateOne(context.Background(), filter, update, opts)
				if err != nil {
					log.Printf("  ERROR: Failed to insert: %v", err)
					skippedDocs++
				} else {
					insertedDocs++
					log.Printf("  ✓ Inserted")
				}
			}

			inDocument = false
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Scanner error: %v", err)
	}

	// Summary
	log.Println("\n" + strings.Repeat("=", 60))
	log.Println("IMPORT SUMMARY")
	log.Println(strings.Repeat("=", 60))
	log.Printf("Total documents found:  %d", totalDocs)
	log.Printf("Documents inserted:     %d", insertedDocs)
	log.Printf("Documents skipped:      %d", skippedDocs)
	if *dryRun {
		log.Println("\nTo actually insert documents, run without --dry-run flag")
	}
	log.Println(strings.Repeat("=", 60))
}

// createGzippedPlaceholder creates a valid gzipped TGS file (Lottie JSON)
func createGzippedPlaceholder(docID int64) ([]byte, error) {
	// Minimal valid Lottie JSON
	lottieJSON := fmt.Sprintf(`{"v":"5.5.7","fr":60,"ip":0,"op":60,"w":512,"h":512,"nm":"Sticker %d","ddd":0,"assets":[],"layers":[]}`, docID)

	// Gzip the JSON
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	_, err := gzWriter.Write([]byte(lottieJSON))
	if err != nil {
		return nil, err
	}
	if err := gzWriter.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
