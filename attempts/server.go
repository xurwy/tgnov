package main

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/proto/mtproto/crypto"
)

var ctr, ctrIsInitialized int
type ConnProp struct { 
	conn net.Conn
	cryp *AesCTR128Crypto
	sessionCreated bool
	pendingQueries map[int64]mtproto.TLObject // Track unanswered queries
}

func handleConnection(conn net.Conn) {
	defer conn.Close();
	cp := &ConnProp{
		conn: conn,
		pendingQueries: make(map[int64]mtproto.TLObject),
	}
	var Nonce, ServerNonce, newNonce, A []byte
	dhOk := false
	for {
		buffer := make([]byte, 1024)
		if n, _ := conn.Read(buffer); n == 0 { break } else {
			fmt.Printf("(%d) %02x\n", n, buffer[:10])
			if authKey, _ := os.ReadFile("auth_key.bin"); len(authKey) == 256 {
				sha1Hash := sha1.Sum(authKey)
				crAuthKey = crypto.NewAuthKey(int64(binary.LittleEndian.Uint64(sha1Hash[12:20])), authKey)
				dhOk = true
			}
			if ctrIsInitialized == 0 { cp.cryp = initializeCTRCodec(buffer, n); ctrIsInitialized = 1 }
			if !dhOk { // handshaking
				decrypted := cryptoCodec.Decrypt(buffer[:n])
				for _, offset := range []int{32, 50, 64, 73} {
					if _, obj, _ := parseFromIncomingMessage(decrypted[offset:]); obj != nil {
						switch obj.(type) {
						case *mtproto.TLReqPqMulti: conn.Write(cp.encode(handleReqPqMulti(obj)))
						case *mtproto.TLReq_DHParams: Nonce, ServerNonce, newNonce, A, _ = handleReqDHParams(cp, obj)
						case *mtproto.TLSetClient_DHParams: handleSetClientDHParams(cp, obj, Nonce, ServerNonce, newNonce, A); dhOk = true
						}
						break
					}
				}
			} else { // authenticated
				fmt.Println("authenticated")
				decrypted := cp.cryp.Decrypt(buffer[:n]); 
				for offset := 0; offset <= len(decrypted)-32; offset++ {
					if offset+16 >= len(decrypted) { continue }
					func() {
						defer func() { recover() }()
						if rawP, err := crAuthKey.AesIgeDecrypt(decrypted[offset:offset+16], padTo16(decrypted[offset+16:])); err == nil && len(rawP) >= 24 {
							fmt.Println("aes err", err)
							salt, sessionId, msgId := int64(binary.LittleEndian.Uint64(rawP[0:8])), int64(binary.LittleEndian.Uint64(rawP[8:16])), int64(binary.LittleEndian.Uint64(rawP[16:24]))
							// Try to decode the message
							tlMsg := bytesToTL2(rawP[16:])
							o := tlMsg.Object
							
							// Show raw TL details
							if len(rawP) >= 28 {
								constructor := int32(binary.LittleEndian.Uint32(rawP[24:28]))
								log.Printf("Raw TL: msgId=%d, constructor=0x%08x (%d), data_len=%d", msgId, uint32(constructor), constructor, len(rawP)-24)
							}
							
							// Send new_session_created for first message
							if !cp.sessionCreated {
								cp.sendNewSessionCreated(msgId, salt, sessionId)
								cp.sessionCreated = true
							}
							
							// Check if this message type needs a response
							needsResponse := true
							if o != nil {
								switch o.(type) {
								case *mtproto.TLMsgsAck:
									needsResponse = false // Acks don't need responses
								}
							}
							
							// Only track messages that need responses
							if needsResponse {
								cp.pendingQueries[msgId] = o
							}
							log.Printf("Decoded msg %d: %T (pending: %d, needs response: %v)", msgId, o, len(cp.pendingQueries), needsResponse)
							
							// Print detailed object info for debugging
							if o != nil {
								log.Printf("Message details: %+v", o)
							}
							
							if o != nil {
								// Process the decoded message
								cp.handleMessage(o, msgId, salt, sessionId)
							} else if needsResponse {
								// Empty message (ping) - send pong
								cp.sendPong(msgId, salt, sessionId)
							}
							
							// Check if there are old pending queries to respond to
							cp.processPendingQueries(salt, sessionId)
							
							ctr++
						}
					}()
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (cp *ConnProp) encode(obj mtproto.TLObject) []byte {
	x := mtproto.NewEncodeBuf(512)
	serializeToBuffer(x, mtproto.GenerateMessageId(), obj)
	return cp.encode_ctr(x.GetBuf())
}

func (cp *ConnProp) encode_ctr(data []byte) []byte {
	size := len(data) / 4; sb := []byte{byte(size)}
	if size >= 127 { sb = make([]byte, 4); binary.LittleEndian.PutUint32(sb, uint32(size<<8|127)) }
	return cp.cryp.Encrypt(append(sb, data...))
}

func (cp *ConnProp) send(body []byte, salt, sessionId, msgId int64) {
	if crAuthKey == nil { return }
	x := mtproto.NewEncodeBuf(512)
	x.Long(salt); x.Long(sessionId); x.Long(mtproto.GenerateMessageId())
	x.Int(1); x.Int(int32(len(body))); x.Bytes(body)
	msgKey, data, _ := crAuthKey.AesIgeEncrypt(x.GetBuf())
	x2 := mtproto.NewEncodeBuf(8 + len(msgKey) + len(data))
	x2.Long(crAuthKey.AuthKeyId()); x2.Bytes(msgKey); x2.Bytes(data)
	cp.conn.Write(cp.encode_ctr(x2.GetBuf()))
}

func (cp *ConnProp) processPendingQueries(salt, sessionId int64) {
	// Auto-respond to old messages if too many are pending
	// This simulates the server catching up on unanswered messages
	if len(cp.pendingQueries) > 10 {
		// Find oldest pending message
		var oldestMsgId int64
		for msgId := range cp.pendingQueries {
			if oldestMsgId == 0 || msgId < oldestMsgId {
				oldestMsgId = msgId
			}
		}
		
		if oldestMsgId != 0 {
			log.Printf("Auto-responding to old pending msg %d", oldestMsgId)
			// Send a generic pong for old unhandled messages
			cp.sendPong(oldestMsgId, salt, sessionId)
		}
	}
}

func (cp *ConnProp) sendPong(msgId, salt, sessionId int64) {
	buf := mtproto.NewEncodeBuf(88)
	buf.Int(-1636331681) // rpc_result wrapper
	buf.Long(msgId)
	buf.Int(0x347773c5) // pong constructor
	buf.Long(msgId) // msg_id
	buf.Long(msgId) // ping_id (using msgId as pingId)
	cp.send(buf.GetBuf(), salt, sessionId, msgId)
	
	// Mark as answered
	delete(cp.pendingQueries, msgId)
	log.Printf("Sent pong for msg %d (remaining pending: %d)", msgId, len(cp.pendingQueries))
}

func (cp *ConnProp) sendNewSessionCreated(firstMsgId, salt, sessionId int64) {
	buf := mtproto.NewEncodeBuf(512)
	buf.Int(-1631450872)
	buf.Long(firstMsgId)
	buf.Long(463380069436767004)
	buf.Long(salt)
	cp.send(buf.GetBuf(), salt, sessionId, firstMsgId)
}

func (cp *ConnProp) handleMessage(o mtproto.TLObject, msgId, salt, sessionId int64) {
	// Handle wrapper messages
	switch obj := o.(type) {
	case *mtproto.TLInvokeWithLayer:
		if obj.Query != nil {
			// Decode the inner query
			innerMsg := bytesToTL2(obj.Query)
			if innerMsg.Object != nil {
				// Show constructor of inner query
				if len(obj.Query) >= 4 {
					innerConstructor := int32(binary.LittleEndian.Uint32(obj.Query[0:4]))
					log.Printf("InvokeWithLayer inner constructor: 0x%08x (%d)", uint32(innerConstructor), innerConstructor)
				}
				log.Printf("InvokeWithLayer contains: %T", innerMsg.Object)
				// Process the inner query recursively - it will handle the response
				cp.handleMessage(innerMsg.Object, msgId, salt, sessionId)
				return // Inner query handles the response and marking as answered
			} else {
				log.Printf("InvokeWithLayer has empty query")
			}
		}
		// If no valid inner query, send empty response
		buf := mtproto.NewEncodeBuf(88)
		buf.Int(-1636331681) // rpc_result
		buf.Long(msgId)
		buf.Int(0) // empty result
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
		cp.markMessageAnswered(msgId)
		return
	case *mtproto.TLInitConnection:
		if obj.Query != nil {
			if queryObj := bytesToTL2(obj.Query).Object; queryObj != nil {
				log.Printf("InitConnection contains: %T", queryObj)
				cp.handleMessage(queryObj, msgId, salt, sessionId)
			} else {
				// Empty query, send empty response
				buf := mtproto.NewEncodeBuf(88)
				buf.Int(-1636331681) // rpc_result
				buf.Long(msgId)
				buf.Int(0) // empty result
				cp.send(buf.GetBuf(), salt, sessionId, msgId)
				cp.markMessageAnswered(msgId)
			}
		}
		return // The inner query handles the response
	}
	
	// Send actual response for the query
	responded := false
	switch obj := o.(type) {
	case *mtproto.TLAuthSendCode:
		buf := mtproto.NewEncodeBuf(128)
		buf.Int(-1636331681) // rpc_result
		buf.Long(msgId)
		buf.Int(1577067522) // auth.sentCode (0x5e002502)
		buf.String("391b8b674cd42b734f0d3daee668846f") // phone_code_hash
		buf.Int(1920364940) // auth.sentCodeTypeSms (0x72a3158c)
		buf.Int(0) // timeout
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
		responded = true
	case *mtproto.TLAuthSignIn:
		buf := mtproto.NewEncodeBuf(200)
		buf.Int(-1636331681) // rpc_result
		buf.Long(msgId)
		buf.Int(525574008) // auth.authorization (0x1f629778)
		buf.Int(-1195615244) // user (0xb8bc5b0c as signed int32)
		buf.Long(777001) // id
		buf.Long(6279878546724348992) // access_hash
		buf.String("Test") // first_name
		buf.String("User") // last_name
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
		responded = true
	case *mtproto.TLLangpackGetLanguages:
		buf := mtproto.NewEncodeBuf(88)
		buf.Int(-1636331681) // rpc_result
		buf.Long(msgId)
		buf.Int(0) // empty result
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
		responded = true
	case *mtproto.TLHelpGetNearestDc:
		buf := mtproto.NewEncodeBuf(88)
		buf.Int(-1636331681) // rpc_result
		buf.Long(msgId)
		buf.Int(-1910548619) // nearestDc (0x8e1a1775 as signed)
		buf.String("ID") // country
		buf.Int(2) // this_dc
		buf.Int(2) // nearest_dc
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
		responded = true
	case *mtproto.TLHelpGetCountriesList:
		buf := mtproto.NewEncodeBuf(88)
		buf.Int(-1636331681) // rpc_result
		buf.Long(msgId)
		buf.Int(-2013012578) // help.countriesList (0x87d0759e as signed)
		buf.Int(365070542) // vector constructor (0x15bc7ace)
		buf.Int(0) // empty vector count
		buf.Int(0) // hash
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
		responded = true
	case *mtproto.TLHelpGetPromoData:
		buf := mtproto.NewEncodeBuf(88)
		buf.Int(-1636331681) // rpc_result
		buf.Long(msgId)
		buf.Int(-1738248309) // help.promoDataEmpty (0x98f6ac75 as signed)
		buf.Int(int32(time.Now().Unix() + 86400)) // expires
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
		responded = true
	case *mtproto.TLHelpGetTermsOfServiceUpdate:
		buf := mtproto.NewEncodeBuf(88)
		buf.Int(-1636331681) // rpc_result
		buf.Long(msgId)
		buf.Int(-484987777) // help.termsOfServiceUpdateEmpty (0xe3309f7f as signed)
		buf.Int(int32(time.Now().Unix() + 86400)) // expires
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
		responded = true
	case *mtproto.TLAccountUpdateStatus:
		buf := mtproto.NewEncodeBuf(88)
		buf.Int(-1636331681) // rpc_result
		buf.Long(msgId)
		buf.Int(-1720552619) // boolTrue (0x997275b5 as signed)
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
		responded = true
	case *mtproto.TLAccountGetNotifySettings:
		buf := mtproto.NewEncodeBuf(88)
		buf.Int(-1636331681) // rpc_result
		buf.Long(msgId)
		buf.Int(-1673946738) // peerNotifySettings (0x9c3d198e as signed)
		buf.Int(1) // flags
		buf.Int(1) // show_previews
		buf.Int(0) // silent
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
		responded = true
	case *mtproto.TLAccountGetContactSignUpNotification:
		buf := mtproto.NewEncodeBuf(88)
		buf.Int(-1636331681) // rpc_result
		buf.Long(msgId)
		buf.Int(-1720552619) // boolTrue (0x997275b5 as signed)
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
		responded = true
	case *mtproto.TLMsgsAck:
		// Just acknowledgment, no response needed
		log.Printf("Received ack for messages: %v", obj.GetMsgIds())
		// Acks are not tracked as pending since they don't need responses
		// They just acknowledge our sent messages
		return // No RPC result needed for acks
	case *mtproto.TLPingDelayDisconnect:
		// Use the dedicated pong sender which handles tracking
		cp.sendPong(msgId, salt, sessionId)
		return // Already marked as answered in sendPong
	default:
		log.Printf("Unhandled message type: %T", obj)
		buf := mtproto.NewEncodeBuf(88)
		buf.Int(-1636331681) // rpc_result
		buf.Long(msgId)
		buf.Int(0) // empty result
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
		responded = true
	}
	
	// Mark this query as answered and remove from pending
	if responded {
		delete(cp.pendingQueries, msgId)
		log.Printf("Answered msg %d (remaining pending: %d)", msgId, len(cp.pendingQueries))
	}
}

func (cp *ConnProp) markMessageAnswered(msgId int64) {
	if _, exists := cp.pendingQueries[msgId]; exists {
		delete(cp.pendingQueries, msgId)
		log.Printf("Marked msg %d as answered (remaining pending: %d)", msgId, len(cp.pendingQueries))
	}
}

func (cp *ConnProp) replyMsg(o mtproto.TLObject, msgId, salt, sessionId int64) {
	switch obj := o.(type) {
	case *mtproto.TLPingDelayDisconnect:
		buf := mtproto.NewEncodeBuf(88)
		buf.Int(0x347773c5); buf.Long(msgId); buf.Long(obj.PingId)
		fmt.Printf("ping_id %d\n", obj.PingId)
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
	case *mtproto.TLDestroySession:
		destroyData := mtproto.NewEncodeBuf(8); destroyData.Long(obj.SessionId)
		buf := mtproto.NewEncodeBuf(32)
		buf.Int(-212046591); buf.Long(msgId); buf.Int(-501201412); buf.Bytes(destroyData.GetBuf())
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
	case *mtproto.TLMsgContainer:
		for _, m := range obj.Messages { cp.replyMsg(m.Object, m.MsgId, salt, sessionId) }
	case *mtproto.TLMsgsAck:
		fmt.Printf("Received ack for messages: %v\n", obj.GetMsgIds())
	}
}

func bytesToTL2(b []byte) *mtproto.TLMessage2 { msg := &mtproto.TLMessage2{}; msg.Decode(mtproto.NewDecodeBuf(b)); return msg }
func padTo16(data []byte) []byte { if rem := len(data) % 16; rem != 0 { data = append(data, make([]byte, 16-rem)...) }; return data }

func main() {
	log.SetFlags(0)
	listener, _ := net.Listen("tcp", ":10443")
	defer listener.Close()
	log.Printf("Server listening on :10443")
	for i := 0; i < 10; i++ { if conn, err := listener.Accept(); err == nil { handleConnection(conn) } }
}