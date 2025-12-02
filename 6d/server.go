package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/proto/mtproto/crypto"
)

type ConnProp struct {
	conn           net.Conn
	aesCtr         *AesCTR128Crypto
	ctrInitialized bool
	connID         int
	authKey        *crypto.AuthKey
	userID         int64 // User ID if authenticated
}

var (
	connCounter int
	connMutex sync.Mutex
	activeConnections sync.Map
)

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Assign connection ID
	connMutex.Lock()
	connCounter++
	connID := connCounter
	connMutex.Unlock()

	cp := &ConnProp{conn: conn, connID: connID}

	// Track active connection
	activeConnections.Store(connID, cp)
	defer activeConnections.Delete(connID)

	logf(1, "[Conn %d] New connection from %s\n", connID, conn.RemoteAddr())

	var nonce, serverNonce, newNonce, a []byte
	buffer := make([]byte, 5000)

	for {
		n, err := conn.Read(buffer)
		if n == 0 {
			logf(1, "[Conn %d] Connection closed\n", connID)
			break
		}
		logf(1, "[Conn %d] Read %d bytes\n", connID, n)
		if err != nil {
			logf(1, "[Conn %d] Read error: %v\n", connID, err)
		}

		if !cp.ctrInitialized {
			cp.aesCtr = initializeCTRCodec(buffer, n)
			cp.ctrInitialized = true
		}

		decrypted := cp.aesCtr.Decrypt(buffer[:n])

		// Try to discover auth key from the data if we don't have one
		if cp.authKey == nil {
			authKey, offset, err := FindAuthKeyInData(decrypted)
			if err != nil {
				logf(1, "[Conn %d] Error finding auth key: %v\n", cp.connID, err)
			} else if authKey != nil {
				cp.authKey = authKey
				logf(1, "[Conn %d] Auth key discovered from data at offset %d: %d\n", cp.connID, offset, authKey.AuthKeyId())

				// Try to load session to get user ID
				session, err := FindSessionByAuthKey(authKey.AuthKeyId())
				if err == nil && session != nil && session.UserID != 0 {
					cp.userID = session.UserID
					logf(1, "[Conn %d] Session loaded, user ID: %d\n", cp.connID, cp.userID)
				}
			}
		}

		if cp.authKey != nil && cp.hasAuthKeyId(decrypted) {
			cp.handleAuthenticated(decrypted)
		} else {
			cp.handleHandshake(decrypted, &nonce, &serverNonce, &newNonce, &a)
		}
	}
}

func (cp *ConnProp) handleHandshake(decrypted []byte, nonce, serverNonce, newNonce, a *[]byte) {
	for _, offset := range []int{32, 50, 64, 73} {
		if offset >= len(decrypted) { continue }

		if _, obj, _ := parseFromIncomingMessage(decrypted[offset:]); obj != nil {
			logf(1, "[Conn %d] Handshake: %T at offset %d\n", cp.connID, obj, offset)
			switch obj.(type) {
				case *mtproto.TLReqPqMulti: cp.conn.Write(cp.encode(handleReqPqMulti(obj)))
				case *mtproto.TLReq_DHParams: *nonce, *serverNonce, *newNonce, *a, _ = handleReqDHParams(cp, obj)
				case *mtproto.TLSetClient_DHParams: handleSetClientDHParams(cp, obj, *nonce, *serverNonce, *newNonce, *a)
			}
			break
		}
	}
}

func (cp *ConnProp) handleAuthenticated(decrypted []byte) {
	if len(decrypted) < 24 { return } // Need at least auth_key_id(8) + msg_key(16)

	logf(2, "[Conn %d] handleAuthenticated: buffer size %d bytes\n", cp.connID, len(decrypted))

	// Find all auth_key_id positions and process messages there
	target := cp.authKey.AuthKeyId()
	offset := 0

	for offset <= len(decrypted)-24 {
		// Look for auth_key_id
		if int64(binary.LittleEndian.Uint64(decrypted[offset:offset+8])) == target {
			logf(2, "[Conn %d] Found auth_key_id at offset %d\n", cp.connID, offset)

			// Try to decrypt message at this position
			msgLen := cp.aesIgeDecrypt(decrypted, offset)
			if msgLen > 0 {
				logf(2, "[Conn %d] Processed message at offset %d, length %d\n", cp.connID, offset, msgLen)
				offset += msgLen // Skip to after this message
			} else {
				offset++ // Auth key ID matched but decrypt failed, continue searching
			}
		} else {
			offset++
		}
	}
}

func (cp *ConnProp) aesIgeDecrypt(decrypted []byte, offset int) int {
	// offset points to auth_key_id, skip it to get to msg_key
	// Format: [auth_key_id:8][msg_key:16][encrypted_data]
	if offset+24 >= len(decrypted) {
		logf(2, "[Conn %d] aesIgeDecrypt: offset %d too close to end (%d bytes)\n", cp.connID, offset, len(decrypted))
		return 0
	}

	msgKeyOffset := offset + 8
	remainingBytes := len(decrypted) - msgKeyOffset - 16

	logf(2, "[Conn %d] Attempting decrypt at offset %d (msgKey at %d), remaining %d bytes\n", cp.connID, offset, msgKeyOffset, remainingBytes)

	// Try to find the correct encrypted data length by trying multiples of 16
	// Start from the end and work backwards to find valid padding
	var rawP []byte
	var err error
	found := false
	validEncLen := 0

	for encLen := (remainingBytes / 16) * 16; encLen >= 16; encLen -= 16 {
		rawP, err = cp.authKey.AesIgeDecrypt(decrypted[msgKeyOffset:msgKeyOffset+16], decrypted[msgKeyOffset+16:msgKeyOffset+16+encLen])
		if err == nil && len(rawP) >= 24 {
			// Try to decode to verify it's valid
			msg := &mtproto.TLMessage2{}
			msg.Decode(mtproto.NewDecodeBuf(rawP[16:]))
			if msg.Object != nil {
				found = true
				validEncLen = encLen
				logf(2, "[Conn %d] Found valid message with encrypted length %d\n", cp.connID, encLen)
				break
			}
		}
	}

	if !found {
		logf(2, "[Conn %d] Could not find valid message at offset %d\n", cp.connID, offset)
		return 0
	}

	// Decode again to get the actual message (we already validated it above)
	msg := &mtproto.TLMessage2{}
	msg.Decode(mtproto.NewDecodeBuf(rawP[16:]))

	salt := int64(binary.LittleEndian.Uint64(rawP[0:8]))
	sessionId := int64(binary.LittleEndian.Uint64(rawP[8:16]))
	msgId := int64(binary.LittleEndian.Uint64(rawP[16:24]))

	logf(1, "[Conn %d] Message: %T at offset %d, msgId: %d\n", cp.connID, msg.Object, offset, msgId)

	// Update session in database on every message
	go func() {
		session := &SessionDoc{
			SessionID:  sessionId,
			AuthKeyID:  cp.authKey.AuthKeyId(),
			UserID:     cp.userID, // Will be 0 if not authenticated
			Salt:       salt,
			LastUsedAt: time.Now(),
		}
		UpdateSession(session)
	}()

	cp.replyMsg(msg.Object, msgId, salt, sessionId)

	// Return the total message length (auth_key_id + msg_key + encrypted data)
	return 8 + 16 + validEncLen
}

func (cp *ConnProp) encode(obj mtproto.TLObject) []byte {
	x := mtproto.NewEncodeBuf(512)
	serializeToBuffer(x, mtproto.GenerateMessageId(), obj)
	return cp.encodeCtr(x.GetBuf())
}

func (cp *ConnProp) encodeCtr(data []byte) []byte {
	size := len(data) / 4
	sb := []byte{byte(size)}
	if size >= 127 {
		sb = make([]byte, 4)
		binary.LittleEndian.PutUint32(sb, uint32(size<<8|127))
	}
	return cp.aesCtr.Encrypt(append(sb, data...))
}

func (cp *ConnProp) send(body []byte, salt, sessionId int64) {
	if cp.authKey == nil { return }
	x := mtproto.NewEncodeBuf(512)
	x.Long(salt); x.Long(sessionId); x.Long(mtproto.GenerateMessageId())
	x.Int(1); x.Int(int32(len(body))); x.Bytes(body)
	msgKey, data, _ := cp.authKey.AesIgeEncrypt(x.GetBuf())
	x2 := mtproto.NewEncodeBuf(8 + len(msgKey) + len(data))
	x2.Long(cp.authKey.AuthKeyId()); x2.Bytes(msgKey); x2.Bytes(data)
	cp.conn.Write(cp.encodeCtr(x2.GetBuf()))
}


func (cp *ConnProp) hasAuthKeyId(data []byte) bool {
	if cp.authKey == nil || len(data) < 8 { return false }
	target := cp.authKey.AuthKeyId()
	for i := 0; i <= len(data)-8; i++ {
		if int64(binary.LittleEndian.Uint64(data[i:i+8])) == target {
			logf(1, "[Conn %d] AuthKeyId found at offset %d\n", cp.connID, i)
			return true
		}
	}
	return false
}

var DEBUG_LVL = func() int {
	if envVal := os.Getenv("DEBUG_LVL"); envVal != "" {
		if level, err := strconv.Atoi(envVal); err == nil {
			return level
		}
	}
	return 1
}()

func logf(level int, format string, args ...interface{}) {
	if level > DEBUG_LVL { return }
	pc, file, line, _ := runtime.Caller(1)
	funcName := runtime.FuncForPC(pc).Name()
	shortName := funcName[strings.LastIndex(funcName, ".")+1:]
	filename := filepath.Base(file)
	timestamp := time.Now().Format("15:04:05.000")
	log.Printf("%s %4d %8s:%3d %20s() | %s", timestamp, level, filename, line, shortName, fmt.Sprintf(format, args...))
}

func main() {
	log.SetFlags(0)

	// Initialize MongoDB
	mongoURL := "mongodb://localhost:27017/telegram"
	if err := InitMongoDB(mongoURL); err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	defer CloseMongoDB()

	listener, _ := net.Listen("tcp", ":10443")
	defer listener.Close()
	log.Printf("Server listening on :10443")
	for i := 0; i < 50; i++ {
		if conn, err := listener.Accept(); err == nil {
			log.Printf("New connection accepted from %s", conn.RemoteAddr())
			go handleConnection(conn)
		}
	}
}