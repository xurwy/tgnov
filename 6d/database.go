package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/teamgram/proto/mtproto/crypto"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	mongoClient          *mongo.Client
	authKeysCollection   *mongo.Collection
	usersCollection      *mongo.Collection
	sessionsCollection   *mongo.Collection
	phoneCodesCollection *mongo.Collection
	fileDataCollection   *mongo.Collection
)

// AuthKeyDoc represents the MongoDB document for auth keys
type AuthKeyDoc struct {
	AuthKeyID  int64     `bson:"auth_key_id"`
	AuthKey    []byte    `bson:"auth_key"`
	CreatedAt  time.Time `bson:"created_at"`
	UpdatedAt  time.Time `bson:"updated_at"`
	LastUsedAt time.Time `bson:"last_used_at"`
}

// UserDoc stores user data following MTProto User type field names
type UserDoc struct {
	ID         int64     `bson:"id"`          // User ID (matches User.ID in protocol)
	AccessHash int64     `bson:"access_hash"` // Access hash (matches User.AccessHash)
	FirstName  string    `bson:"first_name"`  // First name (matches User.FirstName)
	LastName   string    `bson:"last_name"`   // Last name (matches User.LastName)
	Username   string    `bson:"username"`    // Username (matches User.Username)
	Phone      string    `bson:"phone"`       // Phone number (matches User.Phone)

	// Flags from protocol
	Self          bool `bson:"self"`
	Contact       bool `bson:"contact"`
	MutualContact bool `bson:"mutual_contact"`
	Deleted       bool `bson:"deleted"`
	Bot           bool `bson:"bot"`
	Verified      bool `bson:"verified"`
	Restricted    bool `bson:"restricted"`
	Scam          bool `bson:"scam"`
	Fake          bool `bson:"fake"`
	Premium       bool `bson:"premium"`
	Support       bool `bson:"support"`

	CreatedAt  time.Time `bson:"created_at"`
	UpdatedAt  time.Time `bson:"updated_at"`
	LastSeenAt time.Time `bson:"last_seen_at"`
}

// SessionDoc links auth_key_id to user sessions
type SessionDoc struct {
	SessionID  int64     `bson:"session_id"`  // Session ID from client messages
	AuthKeyID  int64     `bson:"auth_key_id"` // Auth key used for this session
	UserID     int64     `bson:"user_id"`     // User ID (0 if not authenticated yet)
	Salt       int64     `bson:"salt"`        // Current salt
	CreatedAt  time.Time `bson:"created_at"`
	UpdatedAt  time.Time `bson:"updated_at"`
	LastUsedAt time.Time `bson:"last_used_at"`
}

// PhoneCodeDoc stores temporary phone verification codes (for auth.sendCode flow)
type PhoneCodeDoc struct {
	PhoneNumber   string    `bson:"phone_number"`     // Phone number
	PhoneCodeHash string    `bson:"phone_code_hash"`  // Hash (matches auth.SentCode.PhoneCodeHash)
	AuthKeyID     int64     `bson:"auth_key_id"`      // Auth key that requested this code
	Code          string    `bson:"code"`             // Actual verification code
	CreatedAt     time.Time `bson:"created_at"`
	ExpiresAt     time.Time `bson:"expires_at"`
	Verified      bool      `bson:"verified"`
}

// FileDataDoc stores file data for upload.getFile responses
type FileDataDoc struct {
	DocumentID int64     `bson:"document_id"` // Document ID from inputDocumentFileLocation
	Data       []byte    `bson:"data"`        // Compressed file data (gzip)
	CreatedAt  time.Time `bson:"created_at"`
	UpdatedAt  time.Time `bson:"updated_at"`
}

// InitMongoDB initializes the MongoDB connection
func InitMongoDB(mongoURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURL))
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Ping to verify connection
	if err := client.Ping(ctx, nil); err != nil {
		return fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	mongoClient = client
	db := client.Database("telegram")

	// Initialize collections
	authKeysCollection = db.Collection("auth_keys")
	usersCollection = db.Collection("users")
	sessionsCollection = db.Collection("sessions")
	phoneCodesCollection = db.Collection("phone_codes")
	fileDataCollection = db.Collection("file_data")

	// Create indexes for auth_keys
	authKeyIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "auth_key_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	}
	_, err = authKeysCollection.Indexes().CreateMany(ctx, authKeyIndexes)
	if err != nil {
		log.Printf("Warning: Could not create auth_keys indexes: %v", err)
	}

	// Create indexes for users
	userIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "phone", Value: 1}},
			Options: options.Index().SetUnique(true).SetSparse(true),
		},
		{
			Keys:    bson.D{{Key: "username", Value: 1}},
			Options: options.Index().SetUnique(true).SetSparse(true),
		},
	}
	_, err = usersCollection.Indexes().CreateMany(ctx, userIndexes)
	if err != nil {
		log.Printf("Warning: Could not create users indexes: %v", err)
	}

	// Create indexes for sessions
	sessionIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "session_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "auth_key_id", Value: 1}},
			Options: options.Index(),
		},
		{
			Keys:    bson.D{{Key: "user_id", Value: 1}},
			Options: options.Index().SetSparse(true),
		},
	}
	_, err = sessionsCollection.Indexes().CreateMany(ctx, sessionIndexes)
	if err != nil {
		log.Printf("Warning: Could not create sessions indexes: %v", err)
	}

	// Create indexes for phone codes
	phoneCodeIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "phone_code_hash", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0), // TTL index
		},
	}
	_, err = phoneCodesCollection.Indexes().CreateMany(ctx, phoneCodeIndexes)
	if err != nil {
		log.Printf("Warning: Could not create phone_codes indexes: %v", err)
	}

	// Create indexes for file_data
	fileDataIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "document_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	}
	_, err = fileDataCollection.Indexes().CreateMany(ctx, fileDataIndexes)
	if err != nil {
		log.Printf("Warning: Could not create file_data indexes: %v", err)
	}

	log.Printf("Connected to MongoDB successfully")
	return nil
}

// SaveAuthKey saves an auth key to MongoDB
func SaveAuthKey(authKey []byte, authKeyID int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	doc := AuthKeyDoc{
		AuthKeyID:  authKeyID,
		AuthKey:    authKey,
		CreatedAt:  now,
		UpdatedAt:  now,
		LastUsedAt: now,
	}

	opts := options.Update().SetUpsert(true)
	filter := bson.M{"auth_key_id": authKeyID}
	update := bson.M{"$set": doc}

	_, err := authKeysCollection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("failed to save auth key: %w", err)
	}

	log.Printf("Auth key saved to MongoDB: %d", authKeyID)
	return nil
}

// LoadAuthKeyByID loads an auth key from MongoDB by auth key ID
func LoadAuthKeyByID(authKeyID int64) (*crypto.AuthKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var doc AuthKeyDoc
	filter := bson.M{"auth_key_id": authKeyID}
	err := authKeysCollection.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil // No auth key found, not an error
		}
		return nil, fmt.Errorf("failed to load auth key: %w", err)
	}

	// Update last used time
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		update := bson.M{"$set": bson.M{"last_used_at": time.Now()}}
		authKeysCollection.UpdateOne(ctx, filter, update)
	}()

	authKey := crypto.NewAuthKey(doc.AuthKeyID, doc.AuthKey)
	return authKey, nil
}


// FindAuthKeyByPrefix searches for an auth key ID in the data and loads it
func FindAuthKeyInData(data []byte) (*crypto.AuthKey, int, error) {
	if len(data) < 8 {
		return nil, -1, nil
	}

	// Search for auth key ID in the data
	for i := 0; i <= len(data)-8; i++ {
		authKeyID := int64(binary.LittleEndian.Uint64(data[i:i+8]))

		// Try to load this auth key from MongoDB
		authKey, err := LoadAuthKeyByID(authKeyID)
		if err != nil {
			continue
		}
		if authKey != nil {
			log.Printf("Auth key ID %d found at offset %d", authKeyID, i)
			return authKey, i, nil
		}
	}

	return nil, -1, nil
}

// User management functions

// FindUserByPhone finds a user by phone number
func FindUserByPhone(phone string) (*UserDoc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user UserDoc
	err := usersCollection.FindOne(ctx, bson.M{"phone": phone}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	return &user, nil
}

// FindUserByID finds a user by ID
func FindUserByID(id int64) (*UserDoc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user UserDoc
	err := usersCollection.FindOne(ctx, bson.M{"id": id}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	return &user, nil
}

// CreateUser creates a new user
func CreateUser(user *UserDoc) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	_, err := usersCollection.InsertOne(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// UpdateUser updates an existing user
func UpdateUser(user *UserDoc) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user.UpdatedAt = time.Now()

	_, err := usersCollection.UpdateOne(
		ctx,
		bson.M{"id": user.ID},
		bson.M{"$set": user},
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

// Session management functions

// CreateSession creates a new session
func CreateSession(session *SessionDoc) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session.CreatedAt = time.Now()
	session.UpdatedAt = time.Now()
	session.LastUsedAt = time.Now()

	_, err := sessionsCollection.InsertOne(ctx, session)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	return nil
}

// FindSessionByAuthKey finds a session by auth key ID
func FindSessionByAuthKey(authKeyID int64) (*SessionDoc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var session SessionDoc
	err := sessionsCollection.FindOne(ctx, bson.M{"auth_key_id": authKeyID}).Decode(&session)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find session: %w", err)
	}
	return &session, nil
}

// UpdateSession updates a session
func UpdateSession(session *SessionDoc) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	session.UpdatedAt = now
	session.LastUsedAt = now

	// Use session_id as the unique identifier
	filter := bson.M{"session_id": session.SessionID}

	// On insert, set created_at; on update, keep existing created_at
	update := bson.M{
		"$set": bson.M{
			"auth_key_id":  session.AuthKeyID,
			"user_id":      session.UserID,
			"salt":         session.Salt,
			"updated_at":   session.UpdatedAt,
			"last_used_at": session.LastUsedAt,
		},
		"$setOnInsert": bson.M{
			"session_id": session.SessionID,
			"created_at": now,
		},
	}

	_, err := sessionsCollection.UpdateOne(ctx, filter, update, options.Update().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}
	return nil
}

// Phone code management functions

// SavePhoneCode saves a phone verification code
func SavePhoneCode(phoneCode *PhoneCodeDoc) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	phoneCode.CreatedAt = time.Now()

	_, err := phoneCodesCollection.InsertOne(ctx, phoneCode)
	if err != nil {
		return fmt.Errorf("failed to save phone code: %w", err)
	}
	return nil
}

// FindPhoneCode finds a phone code by hash
func FindPhoneCode(phoneCodeHash string) (*PhoneCodeDoc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var phoneCode PhoneCodeDoc
	err := phoneCodesCollection.FindOne(ctx, bson.M{"phone_code_hash": phoneCodeHash}).Decode(&phoneCode)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find phone code: %w", err)
	}
	return &phoneCode, nil
}

// MarkPhoneCodeVerified marks a phone code as verified
func MarkPhoneCodeVerified(phoneCodeHash string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := phoneCodesCollection.UpdateOne(
		ctx,
		bson.M{"phone_code_hash": phoneCodeHash},
		bson.M{"$set": bson.M{"verified": true}},
	)
	if err != nil {
		return fmt.Errorf("failed to mark phone code verified: %w", err)
	}
	return nil
}

// File data management functions

// SaveFileData saves file data to MongoDB
func SaveFileData(documentID int64, data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	doc := FileDataDoc{
		DocumentID: documentID,
		Data:       data,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	opts := options.Update().SetUpsert(true)
	filter := bson.M{"document_id": documentID}
	update := bson.M{"$set": doc}

	_, err := fileDataCollection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("failed to save file data: %w", err)
	}

	return nil
}

// FindFileDataByID finds file data by document ID
func FindFileDataByID(documentID int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var doc FileDataDoc
	err := fileDataCollection.FindOne(ctx, bson.M{"document_id": documentID}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find file data: %w", err)
	}
	return doc.Data, nil
}

// CloseMongoDB closes the MongoDB connection
func CloseMongoDB() {
	if mongoClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := mongoClient.Disconnect(ctx); err != nil {
			log.Printf("Error disconnecting from MongoDB: %v", err)
		}
	}
}
