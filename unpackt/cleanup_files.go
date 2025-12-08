// +build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"log"
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
	dryRun := flag.Bool("dry-run", false, "Don't actually delete, just report")
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
	log.Println("Scanning for corrupted files...")

	// Get all files
	cursor, err := collection.Find(context.Background(), bson.M{})
	if err != nil {
		log.Fatalf("Failed to query files: %v", err)
	}
	defer cursor.Close(context.Background())

	var (
		totalFiles     int
		corruptedFiles int
		validFiles     int
		deletedFiles   int
	)

	for cursor.Next(context.Background()) {
		var doc FileDataDoc
		if err := cursor.Decode(&doc); err != nil {
			log.Printf("Failed to decode document: %v", err)
			continue
		}

		totalFiles++

		// Check if file data is valid
		isValid, reason := validateFileData(doc.Data)

		if !isValid {
			corruptedFiles++
			log.Printf("CORRUPTED: Document ID %d (%d bytes) - %s", doc.DocumentID, len(doc.Data), reason)

			// Delete if not dry-run
			if !*dryRun {
				_, err := collection.DeleteOne(context.Background(), bson.M{"document_id": doc.DocumentID})
				if err != nil {
					log.Printf("  ERROR: Failed to delete: %v", err)
				} else {
					deletedFiles++
					log.Printf("  DELETED")
				}
			}
		} else {
			validFiles++
			if totalFiles%100 == 0 {
				log.Printf("Progress: %d files scanned (%d valid, %d corrupted)", totalFiles, validFiles, corruptedFiles)
			}
		}
	}

	if err := cursor.Err(); err != nil {
		log.Fatalf("Cursor error: %v", err)
	}

	// Summary
	log.Println("\n" + "============================================================")
	log.Println("CLEANUP SUMMARY")
	log.Println("============================================================")
	log.Printf("Total files scanned:    %d", totalFiles)
	log.Printf("Valid files:            %d", validFiles)
	log.Printf("Corrupted files found:  %d", corruptedFiles)
	if *dryRun {
		log.Printf("Files deleted:          0 (dry-run mode)")
		log.Println("\nTo actually delete corrupted files, run without --dry-run flag")
	} else {
		log.Printf("Files deleted:          %d", deletedFiles)
	}
	log.Println("============================================================")
}

// validateFileData checks if file data is valid
func validateFileData(data []byte) (bool, string) {
	if len(data) == 0 {
		return false, "empty file"
	}

	// Check if it starts with gzip magic bytes (1f 8b)
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		// Try to decompress to verify it's valid gzip
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return false, fmt.Sprintf("invalid gzip header: %v", err)
		}
		defer reader.Close()

		// Try to read first few bytes to verify decompression works
		buf := make([]byte, 100)
		_, err = reader.Read(buf)
		if err != nil && err.Error() != "EOF" && err.Error() != "unexpected EOF" {
			return false, fmt.Sprintf("gzip decompression failed: %v", err)
		}

		// Valid gzip file
		return true, ""
	}

	// Check for other common file signatures
	signatures := map[string][]byte{
		"JPEG": {0xFF, 0xD8, 0xFF},
		"PNG":  {0x89, 0x50, 0x4E, 0x47},
		"WebP": {0x52, 0x49, 0x46, 0x46},
		"MP4":  {0x66, 0x74, 0x79, 0x70}, // at offset 4
		"WebM": {0x1A, 0x45, 0xDF, 0xA3},
	}

	for format, sig := range signatures {
		if len(data) >= len(sig) {
			if bytes.Equal(data[:len(sig)], sig) {
				return true, ""
			}
			// Special check for MP4 at offset 4
			if format == "MP4" && len(data) >= 8 && bytes.Equal(data[4:8], sig) {
				return true, ""
			}
		}
	}

	// Check if it looks like raw binary data (not all zeros, has variety)
	if len(data) > 100 {
		zeros := 0
		for i := 0; i < 100; i++ {
			if data[i] == 0 {
				zeros++
			}
		}
		// If more than 90% zeros in first 100 bytes, probably corrupted
		if zeros > 90 {
			return false, "file appears to be all zeros"
		}
	}

	// Unknown format but has data - assume valid
	// (could be encrypted, proprietary format, etc.)
	return true, ""
}
