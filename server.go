package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kr/pretty"
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/proto/mtproto/crypto"
)

func getDebugLevel() int {
	if envVal := os.Getenv("DEBUG_LVL"); envVal != "" {
		if level, err := strconv.Atoi(envVal); err == nil {
			return level
		}
	}
	return 1 // default value
}

var DEBUG_LVL int = getDebugLevel()

func logf(level int, format string, args ...interface{}) {
	pc, file, line, _ := runtime.Caller(1)
	funcName := runtime.FuncForPC(pc).Name()
	shortName := funcName[strings.LastIndex(funcName, ".")+1:]
	filename := filepath.Base(file)
	msg := fmt.Sprintf(format, args...)
	if level <= DEBUG_LVL {
		log.Printf("%4d %8s:%3d %20s() | %s", level, filename, line, shortName, msg)
	}
}

var ctrIsInitialized int = 0

type ConnProp struct { // Connection Property
	conn net.Conn
	cryp *AesCTR128Crypto
}

func doReceive(conn net.Conn, cp *ConnProp) (int, []byte) {
	buffer := make([]byte, 1024)
	n, _ := conn.Read(buffer)
	logf(1, "len of data %d", n)
	if ctrIsInitialized == 0 {
		cp.cryp = initializeCTRCodec(buffer, n)
		ctrIsInitialized = 1
	}
	// fmt.Printf("bytes received %d\n", n)
	return n, buffer
}

func unpack(b []byte, n int) (msgId int64, obj mtproto.TLObject) {
	decrypted := cryptoCodec.Decrypt(b[:n])

	arr := []int{32, 50, 64, 73}
	for _, offset := range arr {
		msgId, obj, _ = parseFromIncomingMessage(decrypted[offset:])
		if obj != nil {
			logf(2, "%# v", pretty.Formatter(obj))
			logf(1, "%T", obj)
			return
		}
	}
	return 0, nil
}

func (cp *ConnProp) pack(obj mtproto.TLObject) []byte {
	x := mtproto.NewEncodeBuf(512)
	serializeToBuffer(x, mtproto.GenerateMessageId(), obj)
	return cp.Encode(x)
}

func (cp *ConnProp) Encode(x *mtproto.EncodeBuf) []byte {
	out := x.GetBuf()
	size := len(out) / 4
	sb := func() []byte {
		if size < 127 {
			return []byte{byte(size)}
		}
		sb := make([]byte, 4)
		binary.LittleEndian.PutUint32(sb, uint32(size<<8|127))
		return sb
	}()
	return cp.cryp.Encrypt(append(sb, out...))
}

// a -> ctr -> b -> ige -> c (c++)
// c -> ige -> b -> ctr -> a (golang)

// a -> ctr -> b -> ige -> c (golang)

func handleAuthenticatedMessage(cp *ConnProp, buff []byte, n int) {
	// handleAuthPacket(buff, n)
	// cp.processPackets(buff)
	hasAuthKey := readAuthKey()
	if hasAuthKey && crAuthKey != nil {
		logf(2, "A. Raw received from client: %02x", buff[:n])

		// CTR decrypt returns new buffer
		decrypted := cp.cryp.Decrypt(buff[:n])
		logf(2, "B. After CTR decrypt: %02x", decrypted)

		var rawP []byte
		var err error
		var validOffsets []int

		// First, find all valid offsets - NOW USE THE DECRYPTED BUFFER!
		for offset := 0; offset <= len(decrypted)-16; offset++ {
			// Check if we have enough space for 16-byte msgKey and some data
			if offset+16 < len(decrypted) {
				// Additional bounds checking to prevent slice errors
				if offset >= 0 && offset+16 <= len(decrypted) && offset+16 < len(decrypted) {
					msgKey := decrypted[offset : offset+16]   // Now this uses decrypted data
					encData := padTo16(decrypted[offset+16:]) // And this too

					// Catch panics from AesIgeDecrypt
					func() {
						defer func() {
							if r := recover(); r != nil {
								logf(2, "Panic at offset %d: %v", offset, r)
							}
						}()

						testRawP, testErr := crAuthKey.AesIgeDecrypt(msgKey, encData)

						if testErr == nil && len(testRawP) >= 24 {
							validOffsets = append(validOffsets, offset)
							if offset == 0 {
								logf(2, "Offset 0 decrypted preview: %02x", testRawP[:32])
							}
						}
					}()
				}
			}
		}

		if len(validOffsets) == 0 {
			logf(1, "No valid offset found for AesIgeDecrypt")
			return
		}

		// Log all valid offsets
		logf(1, "Found valid dec. Offset: %v", validOffsets)

		// Use the first valid offset for actual decryption (you can change this)
		chosenOffset := validOffsets[0]
		msgKey := decrypted[chosenOffset : chosenOffset+16]
		encData := padTo16(decrypted[chosenOffset+16:])
		rawP, err = crAuthKey.AesIgeDecrypt(msgKey, encData)

		logf(2, "Using offset %d for decryption, rawp %02x", chosenOffset, rawP)

		if err == nil && len(rawP) >= 24 {
			salt := int64(binary.LittleEndian.Uint64(rawP[0:8]))
			sessionId := int64(binary.LittleEndian.Uint64(rawP[8:16]))
			requestMsgId := int64(binary.LittleEndian.Uint64(rawP[16:24]))

			logf(2, "C. RECEIVED FROM CLIENT:")
			logf(2, "   Salt: 0x%x", salt)
			logf(2, "   SessionId: 0x%x", sessionId)
			logf(2, "   RequestMsgId: 0x%x", requestMsgId)
			logf(2, "   Full decrypted payload: %02x", rawP)

			o := bytesToTL2(rawP[16:]).Object
			logf(1, "%T", o)
			
			// Handle different message types and send appropriate responses
			switch obj := o.(type) {
			case *mtproto.TLPingDelayDisconnect:
				pongData := mtproto.NewEncodeBuf(88)
				pongData.Int(0x347773c5)
				pongData.Long(requestMsgId)
				pongData.Long(obj.PingId)
				cp.sendEncryptedMessage(pongData.GetBuf(), salt, sessionId, requestMsgId, "PingDelayDisconnect") // 0x347773c5 = 880243653
			default:
				if _, isAck := o.(*mtproto.TLMsgsAck); !isAck {	
					pendingRequests[requestMsgId] = fmt.Sprintf("%T", o)
					cp.replyMsg(o, requestMsgId, salt, sessionId)
					markRequestCompleted(requestMsgId, fmt.Sprintf("Unhandled: %T", o))
				}
			}
		}
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	connection = conn
	cp := &ConnProp{conn: conn}
	// readTgnetDat()
	var respObj mtproto.TLObject
	ctrIsInitialized = 0
	var Nonce, ServerNonce, newNonce, A []byte
	var dhOk bool = false

	for {
		n, buff := doReceive(conn, cp)
		if n == 0 {
			break
		}

		if !dhOk {
			_, obj := unpack(buff, n)
			switch obj.(type) {
			case *mtproto.TLReqPqMulti:
				respObj = handleReqPqMulti(obj)
				buffToSend := cp.pack(respObj)
				conn.Write(buffToSend)
			case *mtproto.TLReq_DHParams:
				Nonce, ServerNonce, newNonce, A, _ = handleReqDHParams(cp, obj)
			case *mtproto.TLSetClient_DHParams:
				{
					handleSetClientDHParams(cp, obj, Nonce, ServerNonce, newNonce, A)
					// break
					dhOk = true
				}
			}
		} else {
			handleAuthenticatedMessage(cp, buff, n)
		}
		time.Sleep(500 * time.Millisecond)
	}
	conn.Close()
}

func readAuthKey() bool {
	authKey, err := os.ReadFile("auth_key.bin")
	if err != nil {
		logf(1, "auth_key.bin not found, continuing without it")
		return false
	}

	if len(authKey) != 256 {
		logf(1, "Invalid auth_key.bin size: %d bytes (expected 256)", len(authKey))
		return false
	}

	if bytes.Equal(authKey, make([]byte, 256)) {
		return false
	}

	// Calculate auth key ID from the auth key using the same method as the client
	// The auth key ID is derived from SHA1 hash of the auth key
	sha1Hash := sha1.Sum(authKey)
	authKeyId := int64(binary.LittleEndian.Uint64(sha1Hash[12:20]))

	crAuthKey = crypto.NewAuthKey(authKeyId, authKey)

	// Log the auth key and calculated ID
	logf(2, "Auth key loaded from auth_key.bin: %02x", authKey)
	logf(2, "Calculated auth key ID: 0x%x", authKeyId)

	return true
}

func main() {

	port := ":10443"
	log.SetFlags(0)
	listener, _ := net.Listen("tcp", port)

	defer listener.Close()
	log.Printf("Server is listening on port %s", port)
	for i := 0; i < 10; i++ {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		handleConnection(conn)
	}
}

var pendingRequests map[int64]string = make(map[int64]string)

func (cp *ConnProp) processPackets(encrypted []byte) bool {
	var offset int
	success := true
	for packetCount := 0; offset < len(encrypted) && packetCount < 5; packetCount++ {
		_, packetData, newOffset, err := cp.DecodePacket(encrypted, offset)
		if err != nil || len(packetData) == 0 {
			break
		}
		if cp.processSubPacket(packetData) == nil {
			success = false
		}
		offset = newOffset
	}
	return success
}

var ErrUnexpectedEOF = errors.New("there is no enough data")

func (cp *ConnProp) DecodePacket(in []byte, offset int) (bool, []byte, int, error) {
	if offset >= len(in) {
		return false, nil, offset, ErrUnexpectedEOF
	}
	firstByte := in[offset : offset+1]
	firstByte = cp.cryp.Decrypt(firstByte)
	needAck := (firstByte[0] >> 7) == 1
	packetLen := int(firstByte[0] & 0x7f)
	nextOffset := offset + 1
	if packetLen < 0x7f {
		packetLen = packetLen * 4
	} else {
		packetLen = int(binary.LittleEndian.Uint32(append([]byte{0}, in[nextOffset:nextOffset+3]...)))
		mpacketLen := cp.cryp.Decrypt(in[nextOffset : nextOffset+3])
		nextOffset += 3
		packetLen = int(binary.LittleEndian.Uint32(append(mpacketLen[:], 0))) * 4
	}
	if nextOffset+packetLen > len(in) {
		return false, nil, offset, ErrUnexpectedEOF
	}
	packetData := make([]byte, packetLen)
	copy(packetData, in[nextOffset:nextOffset+packetLen])
	packetData = cp.cryp.Decrypt(packetData)
	return needAck, packetData, nextOffset + packetLen, nil
}
func bytesToTL2(b []byte) *mtproto.TLMessage2 {
	msg := &mtproto.TLMessage2{}
	msg.Decode(mtproto.NewDecodeBuf(b))
	return msg
}
func padTo16(data []byte) []byte {
	if rem := len(data) % 16; rem != 0 {
		data = append(data, make([]byte, 16-rem)...)
	}
	return data
}
func (cp *ConnProp) processSubPacket(decrypted []byte) error {
	if len(decrypted) == 0 {
		os.Exit(0)
	}
	if len(decrypted) <= 40 {
		return nil
	}
	readAuthKey()
	if crAuthKey == nil {
		if AuthKey == nil {
			return nil
		}
		sha1Hash := sha1.Sum(AuthKey)
		crAuthKey = crypto.NewAuthKey(int64(binary.LittleEndian.Uint64(sha1Hash[12:20])), AuthKey)
	}
	rawP, err := crAuthKey.AesIgeDecrypt(decrypted[8:24], padTo16(decrypted[24:]))
	if err != nil || len(rawP) < 24 {
		return fmt.Errorf("decryption failed: %v", err)
	}
	logf(1, "reaching processSubPacket")
	salt := int64(binary.LittleEndian.Uint64(rawP[0:8]))
	sessionId := int64(binary.LittleEndian.Uint64(rawP[8:16]))
	requestMsgId := int64(binary.LittleEndian.Uint64(rawP[16:24]))
	o := bytesToTL2(rawP[16:]).Object
	if _, isAck := o.(*mtproto.TLMsgsAck); !isAck {
		pendingRequests[requestMsgId] = fmt.Sprintf("%T", o)
	}

	cp.replyMsg(o, requestMsgId, salt, sessionId)
	return nil
}
func sessionNew() *mtproto.TLNewSessionCreated {
	s := &mtproto.TLNewSessionCreated{
		Data2: &mtproto.NewSession{
			PredicateName: "new_session_created",
			Constructor:   -1631450872,
			FirstMsgId:    7523238081306948616,
			UniqueId:      7469723214292374799,
			ServerSalt:    -4468521727382002472,
		},
	}
	return s
}
func (cp *ConnProp) sendEncryptedMessage(messageBody []byte, salt, sessionId, requestMsgId int64, responseType string) {
	if crAuthKey == nil {
		cp.sendResponse(messageBody)
		return
	}
	x1 := mtproto.NewEncodeBuf(512)
	x1.Long(salt)
	x1.Long(sessionId)
	x1.Long(mtproto.GenerateMessageId())
	x1.Int(1)
	x1.Int(int32(len(messageBody)))
	x1.Bytes(messageBody)
	msgKey, mtpRawData, _ := crAuthKey.AesIgeEncrypt(x1.GetBuf())
	x := mtproto.NewEncodeBuf(8 + len(msgKey) + len(mtpRawData))
	x.Long(crAuthKey.AuthKeyId())
	x.Bytes(msgKey)
	x.Bytes(mtpRawData)
	cp.conn.Write(cp.Encode(x))
	if requestMsgId != 0 {
		markRequestCompleted(requestMsgId, responseType)
	}
}
func (cp *ConnProp) sendResponse(messageBody []byte) {
	x := mtproto.NewEncodeBuf(512)
	x.Bytes(messageBody)
	cp.conn.Write(cp.Encode(x))
}
func (cp *ConnProp) sendTLObjectResponse(obj mtproto.TLObject) {
	x := mtproto.NewEncodeBuf(512)
	serializeToBuffer(x, mtproto.GenerateMessageId(), obj)
	cp.sendResponse(x.GetBuf())
}
func (cp *ConnProp) sendSessionMsg(salt, sessionId int64) {
	buf := mtproto.NewEncodeBuf(512)
	sessionNew().Encode(buf, 0)
	cp.sendEncryptedMessage(buf.GetBuf(), salt, sessionId, 0, "")
}
func (cp *ConnProp) createRpcResult(requestMsgId int64, resultConstructor int32, resultData []byte) []byte {
	buf := mtproto.NewEncodeBuf(512)
	buf.Int(-212046591)
	buf.Long(requestMsgId)
	buf.Int(resultConstructor)
	if len(resultData) > 0 {
		buf.Bytes(resultData)
	}
	return buf.GetBuf()
}
func markRequestCompleted(requestMsgId int64, responseType string) {
	delete(pendingRequests, requestMsgId)
	logf(1, "Sent %s response to %d, remaining pending: %d", responseType, requestMsgId, len(pendingRequests))
}
func (cp *ConnProp) replyMsg(o mtproto.TLObject, requestMsgId int64, salt int64, sessionId int64) {
	logf(1, "reaching this line %T", o)
	switch obj := o.(type) {
	case *mtproto.TLHelpGetConfig, *mtproto.TLInvokeWithLayer:
		responseType := map[bool]string{true: "InvokeWithLayer", false: "HelpGetConfig"}[fmt.Sprintf("%T", o) == "*mtproto.TLInvokeWithLayer"]
		cp.sendEncryptedMessage(GetConfigRpcResult(requestMsgId), salt, sessionId, requestMsgId, responseType)
	case *mtproto.TLAuthBindTempAuthKey:
		decrypted := obj.EncryptedMessage
		rawP, err := crAuthKey.AesIgeDecrypt(decrypted[8:24], padTo16(decrypted[24:]))
		logf(1, "TLAuthBindTempAuthKey encryted %02x %s", rawP, err)
		cp.sendEncryptedMessage(cp.createRpcResult(requestMsgId, -1720552011, nil), salt, sessionId, requestMsgId, "AuthBindTempAuthKey")
		cp.sendSessionMsg(salt, sessionId)
	// case *mtproto.TLMsgsAck:
	case *mtproto.TLPingDelayDisconnect:
		pongData := mtproto.NewEncodeBuf(16)
		pongData.Long(requestMsgId)
		pongData.Long(obj.PingId)
		cp.sendEncryptedMessage(cp.createRpcResult(requestMsgId, 0x347773c5, pongData.GetBuf()), salt, sessionId, requestMsgId, "PingDelayDisconnect") // 0x347773c5 = 880243653
	case *mtproto.TLDestroySession:
		destroyData := mtproto.NewEncodeBuf(8)
		destroyData.Long(obj.SessionId)
		cp.sendEncryptedMessage(cp.createRpcResult(requestMsgId, -501201412, destroyData.GetBuf()), salt, sessionId, requestMsgId, "DestroySession")
	case *mtproto.TLLangpackGetStrings:
		//what to do?

	case *mtproto.TLMsgContainer:
		for _, message := range obj.Messages {
			cp.replyMsg(message.Object, message.MsgId, salt, sessionId)
		}
	default:
		if _, isAck := o.(*mtproto.TLMsgsAck); !isAck {
			markRequestCompleted(requestMsgId, fmt.Sprintf("Unhandled: %T", o))
		}
	}
}
