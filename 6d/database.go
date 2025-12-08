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
	contactsCollection   *mongo.Collection
	messagesCollection   *mongo.Collection
	dialogsCollection    *mongo.Collection
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

	// Update sequence counters (for proper update synchronization)
	Pts int32 `bson:"pts"` // Persistent timestamp sequence (for messages, profile updates)
	Qts int32 `bson:"qts"` // Query timestamp sequence (for secret chats, encrypted data)
	Seq int32 `bson:"seq"` // Sequence number (for groups, channels)
	Date int32 `bson:"date"` // Unix timestamp of last update

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

// ContactDoc represents a contact relationship between users
type ContactDoc struct {
	OwnerUserID   int64     `bson:"owner_user_id"`   // The user who owns this contact
	ContactUserID int64     `bson:"contact_user_id"` // The user being contacted
	Phone         string    `bson:"phone"`           // Phone number used to import
	ClientID      int64     `bson:"client_id"`       // Client ID from import
	CreatedAt     time.Time `bson:"created_at"`
	UpdatedAt     time.Time `bson:"updated_at"`
	Mutual        bool      `bson:"mutual"` // Whether this is a mutual contact
}

// MessageDoc stores messages between users
type MessageDoc struct {
	ID       int32     `bson:"id"`        // Message ID (unique per dialog)
	DialogID string    `bson:"dialog_id"` // Dialog identifier (e.g., "user_1234_5678")
	FromID   int64     `bson:"from_id"`   // Sender user ID
	PeerID   int64     `bson:"peer_id"`   // Receiver user ID (for direct messages)
	Date     int32     `bson:"date"`      // Unix timestamp
	Message  string    `bson:"message"`   // Message text
	Out      bool      `bson:"out"`       // True if outgoing from FromID
	RandomID int64     `bson:"random_id"` // Random ID from client
	Pts      int32     `bson:"pts"`       // Pts counter for updates
	CreatedAt time.Time `bson:"created_at"`
}

// DialogDoc stores dialog state for each user
type DialogDoc struct {
	UserID           int64     `bson:"user_id"`            // Owner of this dialog
	PeerUserID       int64     `bson:"peer_user_id"`       // The other user in the dialog
	DialogID         string    `bson:"dialog_id"`          // Dialog identifier (e.g., "user_1234_5678")
	TopMessage       int32     `bson:"top_message"`        // ID of the last message
	ReadInboxMaxID   int32     `bson:"read_inbox_max_id"`  // Last read incoming message ID
	ReadOutboxMaxID  int32     `bson:"read_outbox_max_id"` // Last read outgoing message ID
	UnreadCount      int32     `bson:"unread_count"`       // Number of unread messages
	LastMessageDate  int32     `bson:"last_message_date"`  // Date of last message
	CreatedAt        time.Time `bson:"created_at"`
	UpdatedAt        time.Time `bson:"updated_at"`
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
	contactsCollection = db.Collection("contacts")
	messagesCollection = db.Collection("messages")
	dialogsCollection = db.Collection("dialogs")

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

	// Create indexes for contacts
	contactIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "owner_user_id", Value: 1}, {Key: "contact_user_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "owner_user_id", Value: 1}},
			Options: options.Index(),
		},
		{
			Keys:    bson.D{{Key: "phone", Value: 1}},
			Options: options.Index(),
		},
	}
	_, err = contactsCollection.Indexes().CreateMany(ctx, contactIndexes)
	if err != nil {
		log.Printf("Warning: Could not create contacts indexes: %v", err)
	}

	// Create indexes for messages
	messageIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "dialog_id", Value: 1}, {Key: "id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "dialog_id", Value: 1}, {Key: "date", Value: -1}},
			Options: options.Index(),
		},
		{
			Keys:    bson.D{{Key: "random_id", Value: 1}},
			Options: options.Index(),
		},
	}
	_, err = messagesCollection.Indexes().CreateMany(ctx, messageIndexes)
	if err != nil {
		log.Printf("Warning: Could not create messages indexes: %v", err)
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

	// Build update document, excluding username if empty to avoid unique index conflicts
	update := bson.M{
		"$setOnInsert": bson.M{
			"created_at": user.CreatedAt,
		},
		"$set": bson.M{
			"access_hash":    user.AccessHash,
			"first_name":     user.FirstName,
			"last_name":      user.LastName,
			"phone":          user.Phone,
			"self":           user.Self,
			"contact":        user.Contact,
			"mutual_contact": user.MutualContact,
			"deleted":        user.Deleted,
			"bot":            user.Bot,
			"verified":       user.Verified,
			"restricted":     user.Restricted,
			"scam":           user.Scam,
			"fake":           user.Fake,
			"premium":        user.Premium,
			"support":        user.Support,
			"updated_at":     user.UpdatedAt,
			"last_seen_at":   user.LastSeenAt,
		},
	}

	// Only set username if it's not empty
	if user.Username != "" {
		update["$set"].(bson.M)["username"] = user.Username
	}

	_, err := usersCollection.UpdateOne(
		ctx,
		bson.M{"id": user.ID},
		update,
		options.Update().SetUpsert(true),
	)
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

// IncrementUserPts atomically increments a user's pts counter and returns the new value
// ptsCount: how many pts units to increment (usually 1 for single message, 2+ for multiple updates)
func IncrementUserPts(userID int64, ptsCount int32) (int32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use findOneAndUpdate with $inc for atomic increment
	filter := bson.M{"id": userID}
	update := bson.M{
		"$inc": bson.M{"pts": ptsCount},
		"$set": bson.M{
			"date":       int32(time.Now().Unix()),
			"updated_at": time.Now(),
		},
	}

	// Return the updated document
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)

	var user UserDoc
	err := usersCollection.FindOneAndUpdate(ctx, filter, update, opts).Decode(&user)
	if err != nil {
		return 0, fmt.Errorf("failed to increment user pts: %w", err)
	}

	return user.Pts, nil
}

// GetUserState returns the current update state for a user (pts, qts, seq, date)
func GetUserState(userID int64) (pts, qts, seq, date int32, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user UserDoc
	err = usersCollection.FindOne(ctx, bson.M{"id": userID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// User not found, return default state
			return 1, 0, 0, int32(time.Now().Unix()), nil
		}
		return 0, 0, 0, 0, fmt.Errorf("failed to get user state: %w", err)
	}

	// If pts/qts/seq are 0 (newly created user), initialize them
	if user.Pts == 0 {
		user.Pts = 1
	}
	if user.Date == 0 {
		user.Date = int32(time.Now().Unix())
	}

	return user.Pts, user.Qts, user.Seq, user.Date, nil
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

	// Use auth_key_id as the unique identifier (multiple session_ids can share same auth key)
	filter := bson.M{"auth_key_id": session.AuthKeyID}

	// On insert, set created_at; on update, keep existing created_at
	// Build update document - only set user_id if it's non-zero to avoid overwriting
	setFields := bson.M{
		"session_id":   session.SessionID, // Update to latest session_id
		"salt":         session.Salt,
		"updated_at":   session.UpdatedAt,
		"last_used_at": session.LastUsedAt,
	}

	// Only update user_id if it's non-zero (to preserve existing user_id when authenticated)
	if session.UserID != 0 {
		setFields["user_id"] = session.UserID
	}

	update := bson.M{
		"$set": setFields,
		"$setOnInsert": bson.M{
			"auth_key_id": session.AuthKeyID, // Set auth_key_id only on insert
			"created_at":  now,
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

// AddContact adds a contact relationship for a user
func AddContact(ownerUserID, contactUserID int64, phone string, clientID int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	contact := ContactDoc{
		OwnerUserID:   ownerUserID,
		ContactUserID: contactUserID,
		Phone:         phone,
		ClientID:      clientID,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Mutual:        false,
	}

	// Check if reverse contact exists to set mutual
	var reverseContact ContactDoc
	err := contactsCollection.FindOne(ctx, bson.M{
		"owner_user_id":   contactUserID,
		"contact_user_id": ownerUserID,
	}).Decode(&reverseContact)

	if err == nil {
		// Reverse contact exists, mark both as mutual
		contact.Mutual = true
		contactsCollection.UpdateOne(ctx, bson.M{
			"owner_user_id":   contactUserID,
			"contact_user_id": ownerUserID,
		}, bson.M{"$set": bson.M{"mutual": true}})
	}

	_, err = contactsCollection.UpdateOne(
		ctx,
		bson.M{
			"owner_user_id":   ownerUserID,
			"contact_user_id": contactUserID,
		},
		bson.M{"$set": contact},
		options.Update().SetUpsert(true),
	)
	return err
}

// GetContacts gets all contacts for a user
func GetContacts(ownerUserID int64) ([]ContactDoc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := contactsCollection.Find(ctx, bson.M{"owner_user_id": ownerUserID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var contacts []ContactDoc
	if err := cursor.All(ctx, &contacts); err != nil {
		return nil, err
	}
	return contacts, nil
}

// SaveMessage saves a message to the database
func SaveMessage(msg *MessageDoc) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := messagesCollection.InsertOne(ctx, msg)
	return err
}

// GetNextMessageID gets the next message ID for a dialog
func GetNextMessageID(dialogID string) (int32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Find the highest message ID in this dialog
	opts := options.FindOne().SetSort(bson.D{{Key: "id", Value: -1}})
	var lastMsg MessageDoc
	err := messagesCollection.FindOne(ctx, bson.M{"dialog_id": dialogID}, opts).Decode(&lastMsg)

	if err == mongo.ErrNoDocuments {
		return 1, nil // First message
	}
	if err != nil {
		return 0, err
	}
	return lastMsg.ID + 1, nil
}

// GetMessages retrieves messages from a dialog
func GetMessages(dialogID string, limit int32) ([]MessageDoc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.D{{Key: "date", Value: -1}}).SetLimit(int64(limit))
	cursor, err := messagesCollection.Find(ctx, bson.M{"dialog_id": dialogID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var messages []MessageDoc
	if err := cursor.All(ctx, &messages); err != nil {
		return nil, err
	}
	return messages, nil
}

// GetMessageByID retrieves a specific message by dialog_id and message id
func GetMessageByID(dialogID string, messageID int32) (*MessageDoc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var msg MessageDoc
	err := messagesCollection.FindOne(ctx, bson.M{
		"dialog_id": dialogID,
		"id":        messageID,
	}).Decode(&msg)

	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &msg, nil
}

// GetDialogID generates a unique dialog ID for two users
func GetDialogID(userID1, userID2 int64) string {
	// Always use smaller ID first for consistency
	if userID1 > userID2 {
		userID1, userID2 = userID2, userID1
	}
	return fmt.Sprintf("user_%d_%d", userID1, userID2)
}

// UpdateDialog updates or creates a dialog for a user
func UpdateDialog(userID, peerUserID int64, messageID, messageDate int32, isOutgoing bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dialogID := GetDialogID(userID, peerUserID)

	filter := bson.M{
		"user_id":      userID,
		"peer_user_id": peerUserID,
	}

	update := bson.M{
		"$set": bson.M{
			"dialog_id":         dialogID,
			"top_message":       messageID,
			"last_message_date": messageDate,
			"updated_at":        time.Now(),
		},
		"$setOnInsert": bson.M{
			"read_inbox_max_id":  int32(0),
			"read_outbox_max_id": int32(0),
			"unread_count":       int32(0),
			"created_at":         time.Now(),
		},
	}

	// If this is an incoming message, increment unread count
	if !isOutgoing {
		update["$inc"] = bson.M{"unread_count": 1}
	}

	opts := options.Update().SetUpsert(true)
	_, err := dialogsCollection.UpdateOne(ctx, filter, update, opts)
	return err
}

// GetDialogs retrieves all dialogs for a user
func GetDialogs(userID int64, limit int32) ([]DialogDoc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().
		SetSort(bson.D{{Key: "last_message_date", Value: -1}}).
		SetLimit(int64(limit))

	cursor, err := dialogsCollection.Find(ctx, bson.M{"user_id": userID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var dialogs []DialogDoc
	if err := cursor.All(ctx, &dialogs); err != nil {
		return nil, err
	}
	return dialogs, nil
}

// GetPendingMessages retrieves messages that haven't been delivered to a user yet
func GetPendingMessages(userID int64, lastPts int32) ([]MessageDoc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Find messages where:
	// 1. The user is the recipient (peer_id = userID and out = false from sender's perspective)
	// 2. The pts is greater than the user's current pts
	filter := bson.M{
		"peer_id": userID,
		"pts":     bson.M{"$gt": lastPts},
	}

	opts := options.Find().SetSort(bson.D{{Key: "pts", Value: 1}})
	cursor, err := messagesCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var messages []MessageDoc
	if err := cursor.All(ctx, &messages); err != nil {
		return nil, err
	}
	return messages, nil
}

// UpdateUserPts sets a user's pts value (used after delivering updates)
func UpdateUserPts(userID int64, newPts int32) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"id": userID}
	update := bson.M{
		"$set": bson.M{
			"pts":        newPts,
			"updated_at": time.Now(),
		},
	}

	_, err := usersCollection.UpdateOne(ctx, filter, update)
	return err
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
