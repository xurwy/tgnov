package main

import (
	"crypto/rand"
	"log"
	"math/big"
	"time"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/proto/mtproto/crypto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// HandleAuthSendCode handles TL_auth_sendCode requests
func (cp *ConnProp) HandleAuthSendCode(obj *mtproto.TLAuthSendCode, msgId, salt, sessionId int64) {
	phoneNumber := obj.GetPhoneNumber()
	logf(1, "[Conn %d] auth.sendCode for phone: %s\n", cp.connID, phoneNumber)

	// Check if this auth key already has a user
	if cp.userID != 0 {
		logf(1, "[Conn %d] Auth key already has user %d, ignoring sendCode\n", cp.connID, cp.userID)
		cp.sendError(msgId, salt, sessionId, 400, "SESSION_PASSWORD_NEEDED")
		return
	}

	// Generate phone code hash
	phoneCodeHash := crypto.GenerateStringNonce(16)

	// Generate a random 5-digit code
	code := generateVerificationCode(5)

	// Save to database with auth_key_id
	phoneCodeDoc := &PhoneCodeDoc{
		PhoneNumber:   phoneNumber,
		PhoneCodeHash: phoneCodeHash,
		AuthKeyID:     cp.authKey.AuthKeyId(),
		Code:          code,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		Verified:      false,
	}

	if err := SavePhoneCode(phoneCodeDoc); err != nil {
		logf(1, "[Conn %d] Failed to save phone code: %v\n", cp.connID, err)
		return
	}

	// In production, send SMS here
	log.Printf("[Conn %d] Verification code for %s: %s (hash: %s)", cp.connID, phoneNumber, code, phoneCodeHash)

	// Send response
	result := &mtproto.TLAuthSentCode{
		Data2: &mtproto.Auth_SentCode{
			PredicateName: "auth_sentCode",
			Constructor:   1577067778,
			Type: &mtproto.Auth_SentCodeType{
				PredicateName:      "auth_sentCodeTypeSms",
				Constructor:        -1073693790,
				Length:             5,
				Nonce:              nil,
				PlayIntegrityNonce: nil,
			},
			PhoneCodeHash: phoneCodeHash,
			NextType: &mtproto.Auth_CodeType{
				PredicateName: "auth_codeTypeSms",
				Constructor:   1923290508,
			},
			Timeout: &wrapperspb.Int32Value{Value: 60},
		},
	}

	buf := mtproto.NewEncodeBuf(512)
	buf.Int(-212046591)
	buf.Long(msgId)     
	result.Encode(buf, 158)
	cp.send(buf.GetBuf(), salt, sessionId)
}

// HandleAuthSignIn handles TL_auth_signIn requests
func (cp *ConnProp) HandleAuthSignIn(obj *mtproto.TLAuthSignIn, msgId, salt, sessionId int64) {
	phoneNumber := obj.GetPhoneNumber()
	phoneCodeHash := obj.GetPhoneCodeHash()

	logf(1, "[Conn %d] auth.signIn for phone: %s\n", cp.connID, phoneNumber)

	// Check if already authenticated
	if cp.userID != 0 {
		logf(1, "[Conn %d] Already authenticated as user %d\n", cp.connID, cp.userID)
		// User already logged in, just return their info
		user, _ := FindUserByID(cp.userID)
		if user != nil {
			cp.createSessionForUser(user, msgId, salt, sessionId)
		}
		return
	}

	// Verify phone code
	phoneCodeDoc, err := FindPhoneCode(phoneCodeHash)
	if err != nil || phoneCodeDoc == nil {
		logf(1, "[Conn %d] Invalid phone code hash\n", cp.connID)
		cp.sendError(msgId, salt, sessionId, 400, "PHONE_CODE_HASH_EMPTY")
		return
	}

	// Verify this phone code belongs to this auth key
	if phoneCodeDoc.AuthKeyID != cp.authKey.AuthKeyId() {
		logf(1, "[Conn %d] Phone code auth key mismatch\n", cp.connID)
		cp.sendError(msgId, salt, sessionId, 400, "PHONE_CODE_HASH_EMPTY")
		return
	}

	if phoneCodeDoc.PhoneNumber != phoneNumber {
		logf(1, "[Conn %d] Phone number mismatch\n", cp.connID)
		cp.sendError(msgId, salt, sessionId, 400, "PHONE_NUMBER_INVALID")
		return
	}

	if time.Now().After(phoneCodeDoc.ExpiresAt) {
		logf(1, "[Conn %d] Phone code expired\n", cp.connID)
		cp.sendError(msgId, salt, sessionId, 400, "PHONE_CODE_EXPIRED")
		return
	}

	// Mark code as verified
	MarkPhoneCodeVerified(phoneCodeHash)

	// Check if user exists
	user, err := FindUserByPhone(phoneNumber)
	if err != nil {
		logf(1, "[Conn %d] Database error: %v\n", cp.connID, err)
		cp.sendError(msgId, salt, sessionId, 500, "INTERNAL_SERVER_ERROR")
		return
	}

	if user == nil {
		// User doesn't exist, need to sign up
		logf(1, "[Conn %d] User not found, sending authorizationSignUpRequired\n", cp.connID)
		result := &mtproto.TLAuthAuthorizationSignUpRequired{
			Data2: &mtproto.Auth_Authorization{
				PredicateName:   "auth_authorizationSignUpRequired",
				Constructor:     1148485274,
				FutureAuthToken: nil,
			},
		}

		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)     // original request msg_id
		result.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
		return
	}

	// User exists, create session and return authorization
	cp.createSessionForUser(user, msgId, salt, sessionId)
}

// HandleAuthSignUp handles TL_auth_signUp requests
func (cp *ConnProp) HandleAuthSignUp(obj *mtproto.TLAuthSignUp, msgId, salt, sessionId int64) {
	phoneNumber := obj.GetPhoneNumber()
	phoneCodeHash := obj.GetPhoneCodeHash()
	firstName := obj.GetFirstName()
	lastName := obj.GetLastName()

	logf(1, "[Conn %d] auth.signUp for phone: %s, name: %s %s\n", cp.connID, phoneNumber, firstName, lastName)

	// Check if already authenticated
	if cp.userID != 0 {
		logf(1, "[Conn %d] Already authenticated as user %d\n", cp.connID, cp.userID)
		user, _ := FindUserByID(cp.userID)
		if user != nil {
			cp.createSessionForUser(user, msgId, salt, sessionId)
		}
		return
	}

	// Verify phone code
	phoneCodeDoc, err := FindPhoneCode(phoneCodeHash)
	if err != nil || phoneCodeDoc == nil {
		logf(1, "[Conn %d] Invalid phone code hash\n", cp.connID)
		cp.sendError(msgId, salt, sessionId, 400, "PHONE_CODE_HASH_EMPTY")
		return
	}

	// Verify this phone code belongs to this auth key
	if phoneCodeDoc.AuthKeyID != cp.authKey.AuthKeyId() {
		logf(1, "[Conn %d] Phone code auth key mismatch\n", cp.connID)
		cp.sendError(msgId, salt, sessionId, 400, "PHONE_CODE_HASH_EMPTY")
		return
	}

	if phoneCodeDoc.PhoneNumber != phoneNumber {
		logf(1, "[Conn %d] Phone number mismatch\n", cp.connID)
		cp.sendError(msgId, salt, sessionId, 400, "PHONE_NUMBER_INVALID")
		return
	}

	if !phoneCodeDoc.Verified {
		logf(1, "[Conn %d] Phone code not verified\n", cp.connID)
		cp.sendError(msgId, salt, sessionId, 400, "PHONE_CODE_INVALID")
		return
	}

	// Check if user already exists
	existingUser, _ := FindUserByPhone(phoneNumber)
	if existingUser != nil {
		logf(1, "[Conn %d] User already exists\n", cp.connID)
		cp.sendError(msgId, salt, sessionId, 400, "PHONE_NUMBER_OCCUPIED")
		return
	}

	// Generate new user ID and access hash
	userID := generateUserID()
	accessHash := generateAccessHash()

	// Create new user
	user := &UserDoc{
		ID:            userID,
		AccessHash:    accessHash,
		FirstName:     firstName,
		LastName:      lastName,
		Phone:         phoneNumber,
		Self:          true,
		Contact:       true,
		MutualContact: true,
		Deleted:       false,
		Bot:           false,
		Verified:      false,
		Restricted:    false,
		Scam:          false,
		Fake:          false,
		Premium:       false,
		Support:       false,
		LastSeenAt:    time.Now(),
	}

	if err := CreateUser(user); err != nil {
		logf(1, "[Conn %d] Failed to create user: %v\n", cp.connID, err)
		cp.sendError(msgId, salt, sessionId, 500, "INTERNAL_SERVER_ERROR")
		return
	}

	logf(1, "[Conn %d] Created new user ID: %d\n", cp.connID, userID)

	// Create session and return authorization
	cp.createSessionForUser(user, msgId, salt, sessionId)
}

// Helper: Create session for user and send auth.authorization
func (cp *ConnProp) createSessionForUser(user *UserDoc, msgId, salt, sessionId int64) {
	// Create or update session in database
	session := &SessionDoc{
		SessionID:  sessionId,
		AuthKeyID:  cp.authKey.AuthKeyId(),
		UserID:     user.ID,
		Salt:       salt,
		LastUsedAt: time.Now(),
	}

	if err := UpdateSession(session); err != nil {
		logf(1, "[Conn %d] Failed to save session: %v\n", cp.connID, err)
	}

	// Store user ID in connection for future requests
	cp.userID = user.ID

	logf(1, "[Conn %d] User logged in: %d (%s)\n", cp.connID, user.ID, user.Phone)

	// Send auth.authorization response
	result := &mtproto.TLAuthAuthorization{
		Data2: &mtproto.Auth_Authorization{
			PredicateName:   "auth_authorization",
			Constructor:     782418132,
			FutureAuthToken: nil,
			User: &mtproto.User{
				PredicateName: "user",
				Constructor:   -1885878744,
				Id:            user.ID,
				Self:          user.Self,
				Contact:       user.Contact,
				MutualContact: user.MutualContact,
				AccessHash: &wrapperspb.Int64Value{
					Value: user.AccessHash,
				},
				FirstName: &wrapperspb.StringValue{
					Value: user.FirstName,
				},
				LastName: &wrapperspb.StringValue{
					Value: user.LastName,
				},
				Phone: &wrapperspb.StringValue{
					Value: user.Phone,
				},
				Status: &mtproto.UserStatus{
					PredicateName: "userStatusOnline",
					Constructor:   -306628279,
					Expires:       int32(time.Now().Unix() + 3600),
				},
				RestrictionReason: nil,
				Usernames:         nil,
			},
		},
	}

	buf := mtproto.NewEncodeBuf(512)
	buf.Int(-212046591) // rpc_result constructor
	buf.Long(msgId)     // original request msg_id
	result.Encode(buf, 158)
	cp.send(buf.GetBuf(), salt, sessionId)
}

// Helper: Send error response
func (cp *ConnProp) sendError(msgId, salt, sessionId int64, code int32, text string) {
	logf(1, "[Conn %d] Sending error: %d %s\n", cp.connID, code, text)
}

// Helper: Generate verification code (static for testing)
func generateVerificationCode(length int) string {
	// TODO: In production, generate random code and send via SMS
	// For now, always return "12345" for testing
	return "12345"
}

// Helper: Generate user ID
func generateUserID() int64 {
	// Generate random positive int64
	n, _ := rand.Int(rand.Reader, big.NewInt(9000000000))
	return n.Int64() + 1000000000 // Range: 1B to 10B
}

// Helper: Generate access hash
func generateAccessHash() int64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFFFFFFFFFF))
	return n.Int64()
}
