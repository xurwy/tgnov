// +build ignore

package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"flag"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/teamgram/proto/mtproto"
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
	mappingsFile := flag.String("mappings", "document_mappings.txt", "Mappings file")
	mongoURL := flag.String("mongo", "mongodb://localhost:27017/telegram", "MongoDB connection URL")
	dryRun := flag.Bool("dry-run", false, "Don't actually insert, just report")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Connect to MongoDB (only print message, actual connection done per-insert)
	if !*dryRun {
		log.Printf("Will insert into MongoDB: %s", *mongoURL)
	}

	log.Printf("Reading mappings from: %s", *mappingsFile)

	// Read mappings file
	file, err := os.Open(*mappingsFile)
	if err != nil {
		log.Fatalf("Failed to open mappings file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(bufio.NewReader(file))
	reader.Comment = '#'

	records, err := reader.ReadAll()
	if err != nil {
		log.Fatalf("Failed to read CSV: %v", err)
	}

	var (
		totalMappings  int
		extractedFiles int
		failedFiles    int
		insertedFiles  int
	)

	for _, record := range records {
		if len(record) != 6 {
			continue
		}

		documentID, _ := strconv.ParseInt(record[0], 10, 64)
		receivedFile := record[4]
		offset, _ := strconv.Atoi(record[5])

		totalMappings++

		log.Printf("\n[%d/%d] Processing document ID: %d", totalMappings, len(records), documentID)
		log.Printf("  Received file: %s", receivedFile)
		log.Printf("  Offset: %d", offset)

		// Read the binary file
		data, err := os.ReadFile(receivedFile)
		if err != nil {
			log.Printf("  ERROR: Failed to read file: %v", err)
			failedFiles++
			continue
		}

		log.Printf("  File size: %d bytes", len(data))

		// Skip to offset if needed
		if offset > 0 && offset < len(data) {
			data = data[offset:]
			log.Printf("  After offset: %d bytes", len(data))
		}

		// Try to decode as TLRpcResult
		dbuf := mtproto.NewDecodeBuf(data)

		// Manually parse rpc_result structure
		constructor := dbuf.Int()
		log.Printf("  Constructor at offset: 0x%x (%d)", uint32(constructor), constructor)

		// Check if it's rpc_result (-212046591 = 0xf35c6d01)
		if constructor != -212046591 {
			log.Printf("  ERROR: Expected rpc_result constructor, got: 0x%x", uint32(constructor))
			failedFiles++
			continue
		}

		// Read req_msg_id (8 bytes)
		reqMsgId := dbuf.Long()
		log.Printf("  ReqMsgId: %d", reqMsgId)

		// Read upload.file constructor
		uploadConstructor := dbuf.Int()
		log.Printf("  Upload constructor: 0x%x (%d)", uint32(uploadConstructor), uploadConstructor)

		// Manually decode upload.file structure
		// upload.file#96a18d5 type:storage.FileType mtime:int bytes:bytes = upload.File;

		// Read storage.FileType constructor
		fileTypeConstructor := dbuf.Int()
		log.Printf("  FileType constructor: 0x%x", uint32(fileTypeConstructor))

		// Read mtime (int)
		mtime := dbuf.Int()
		log.Printf("  Mtime: %d", mtime)

		// Read bytes (using StringBytes which handles the length prefix)
		fileBytes := dbuf.StringBytes()
		if dbuf.GetError() != nil {
			log.Printf("  ERROR: Failed to read bytes: %v", dbuf.GetError())
			failedFiles++
			continue
		}
		log.Printf("  Extracted bytes: %d bytes", len(fileBytes))

		// Check if it's valid gzip
		if len(fileBytes) >= 2 && fileBytes[0] == 0x1f && fileBytes[1] == 0x8b {
			log.Printf("  ✓ Valid gzip header detected")
		} else {
			log.Printf("  ⚠ Warning: Not a gzip file (first bytes: 0x%02x 0x%02x)", fileBytes[0], fileBytes[1])
		}

		extractedFiles++

		// Insert into MongoDB
		if !*dryRun {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			client, _ := mongo.Connect(ctx, options.Client().ApplyURI(*mongoURL))
			db := client.Database("telegram")
			collection := db.Collection("file_data")

			doc := FileDataDoc{
				DocumentID: documentID,
				Data:       fileBytes,
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			}

			filter := bson.M{"document_id": documentID}
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

			_, err := collection.UpdateOne(ctx, filter, update, opts)
			if err != nil {
				log.Printf("  ERROR: Failed to insert: %v", err)
				failedFiles++
			} else {
				insertedFiles++
				log.Printf("  ✓ Inserted into MongoDB")
			}

			client.Disconnect(ctx)
			cancel()
		}
	}

	// Summary
	log.Println("\n" + strings.Repeat("=", 60))
	log.Println("EXTRACTION SUMMARY")
	log.Println(strings.Repeat("=", 60))
	log.Printf("Total mappings processed:  %d", totalMappings)
	log.Printf("Files extracted:           %d", extractedFiles)
	log.Printf("Files failed:              %d", failedFiles)
	if *dryRun {
		log.Printf("Files inserted:            0 (dry-run mode)")
		log.Println("\nTo actually insert files, run without --dry-run flag")
	} else {
		log.Printf("Files inserted:            %d", insertedFiles)
	}
	log.Println(strings.Repeat("=", 60))
}
