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
var msgCounter int

type ServerMessage struct {
	msgId int64
	msgType string  // "new_session", "rpc_result", etc
	clientRequestId int64
	acknowledged bool
	content []byte
}

type ConnProp struct { 
	conn net.Conn
	cryp *AesCTR128Crypto 
	clientRequests map[int64]string  // Client msgId -> request type
	serverMessages map[int64]*ServerMessage  // Server msgId -> message info
	requestState map[int64]string  // Client request -> state ("pending", "session_sent", "completed")
}

func handleConnection(conn net.Conn) {
	defer conn.Close();
	cp := &ConnProp{
		conn: conn, 
		clientRequests: make(map[int64]string),
		serverMessages: make(map[int64]*ServerMessage),
		requestState: make(map[int64]string),
	}
	var Nonce, ServerNonce, newNonce, A []byte
	dhOk := false
	for {
		buffer := make([]byte, 1024)
		if n, _ := conn.Read(buffer); n == 0 { break } else {
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
				decrypted := cp.cryp.Decrypt(buffer[:n]); 
				for offset := 0; offset <= len(decrypted)-32; offset++ {
					if offset+16 >= len(decrypted) { continue }
					func() {
						defer func() { recover() }()
						if rawP, err := crAuthKey.AesIgeDecrypt(decrypted[offset:offset+16], padTo16(decrypted[offset+16:])); err == nil && len(rawP) >= 24 {
							salt, sessionId, msgId := int64(binary.LittleEndian.Uint64(rawP[0:8])), int64(binary.LittleEndian.Uint64(rawP[8:16])), int64(binary.LittleEndian.Uint64(rawP[16:24]))
							if o := bytesToTL2(rawP[16:]).Object; o != nil { 
								msgCounter++
								fmt.Printf("--> %03d_sent_data.bin\n", msgCounter)
								fmt.Printf("MsgId: %d\n", msgId)
								
								switch obj := o.(type) {
								case *mtproto.TLInvokeWithLayer:
									fmt.Printf("Offset xxx: constructor:CRC32_invokeWithLayer\n")
									
									// Parse the query inside invokeWithLayer
									queryObj := cp.parseInvokeWithLayerQuery(obj)
									var queryName string
									if queryObj != nil {
										queryName = fmt.Sprintf("%T", queryObj)
									} else {
										// Debug: print raw query bytes
										fmt.Printf("  Query bytes (%d): %x\n", len(obj.Query), obj.Query)
									}
									fmt.Printf("  Query: %s\n\n", queryName)
									
									// Track this client request with the actual query
									cp.clientRequests[msgId] = queryName
									cp.requestState[msgId] = "pending"
									
									// Send new_session_created
									msgCounter++
									fmt.Printf("<-- %03d_received_data.bin\n", msgCounter)
									serverMsgId := mtproto.GenerateMessageId()
									fmt.Printf("MsgId: %d\n", serverMsgId)
									fmt.Printf("Offset 84: data2:{predicate_name:\"new_session_created\"  constructor:CRC32_new_session_created  first_msg_id:%d}\n\n", msgId)
									
									buf := mtproto.NewEncodeBuf(512)
									buf.Int(-1631450872) 
									buf.Long(msgId) 
									buf.Long(1) 
									buf.Long(salt)
									
									// Track this server message  
									cp.serverMessages[serverMsgId] = &ServerMessage{
										msgId: serverMsgId,
										msgType: "new_session",
										clientRequestId: msgId,
										acknowledged: false,
										content: buf.GetBuf(),
									}
									
									cp.sendWithMsgId(buf.GetBuf(), salt, sessionId, serverMsgId)
									cp.requestState[msgId] = "session_sent"
									
								default:
									log.Printf("%4d %T\n", ctr, o) 
									cp.replyMsg(o, msgId, salt, sessionId)
								}; ctr++ }
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
	cp.sendWithMsgId(body, salt, sessionId, mtproto.GenerateMessageId())
}

func (cp *ConnProp) sendWithMsgId(body []byte, salt, sessionId, serverMsgId int64) {
	if crAuthKey == nil { return }
	x := mtproto.NewEncodeBuf(512)
	x.Long(salt); x.Long(sessionId); x.Long(serverMsgId)
	x.Int(1); x.Int(int32(len(body))); x.Bytes(body)
	msgKey, data, _ := crAuthKey.AesIgeEncrypt(x.GetBuf())
	x2 := mtproto.NewEncodeBuf(8 + len(msgKey) + len(data))
	x2.Long(crAuthKey.AuthKeyId()); x2.Bytes(msgKey); x2.Bytes(data)
	cp.conn.Write(cp.encode_ctr(x2.GetBuf()))
}

func (cp *ConnProp) replyMsg(o mtproto.TLObject, msgId, salt, sessionId int64) {
	switch obj := o.(type) {
	case *mtproto.TLMsgsAck:
		msgCounter++
		fmt.Printf("--> %03d_sent_data.bin\n", msgCounter)
		fmt.Printf("MsgId: %d\n", msgId)
		
		ackedMsgIds := obj.GetMsgIds()
		if len(ackedMsgIds) > 0 {
			fmt.Printf("Offset 76: data2:{predicate_name:\"msgs_ack\"  constructor:CRC32_msgs_ack  msg_ids:%d}\n\n", ackedMsgIds[0])
			
			// Process each acknowledged message
			for _, ackMsgId := range ackedMsgIds {
				serverMsg, exists := cp.serverMessages[ackMsgId]
				if exists && !serverMsg.acknowledged {
					serverMsg.acknowledged = true
					cp.processAcknowledgment(serverMsg, salt, sessionId)
				}
			}
		}
		
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
	}
}

func (cp *ConnProp) parseInvokeWithLayerQuery(obj *mtproto.TLInvokeWithLayer) mtproto.TLObject {
	if len(obj.Query) == 0 {
		return nil
	}
	
	// Debug: show first few bytes
	fmt.Printf("  First 12 bytes: %x\n", obj.Query[:min(12, len(obj.Query))])
	
	// Try to decode the query bytes directly
	queryBuf := mtproto.NewDecodeBuf(obj.Query)
	
	// First try to read as a TL object directly
	if len(obj.Query) >= 4 {
		constructor := queryBuf.Int()
		fmt.Printf("  Constructor: %x (%d)\n", constructor, constructor)
		
		// Check for known constructors
		if constructor == int32(mtproto.CRC32_initConnection_c1cd5ea9) {
			// We know this is initConnection, let's manually find the inner query
			// The structure is: constructor + api_id + device_model + ... + query
			// Let's look at the end of the bytes for langpack_getLanguages
			queryBytes := obj.Query
			
			// Look for langpack_getLanguages constructor at the end
			if len(queryBytes) >= 8 {
				// Try different positions near the end
				for i := len(queryBytes) - 8; i >= len(queryBytes) - 20 && i >= 0; i-- {
					if len(queryBytes) >= i+4 {
						possibleConstructor := int32(binary.LittleEndian.Uint32(queryBytes[i:i+4]))
						fmt.Printf("  Checking at pos %d: %x\n", i, possibleConstructor)
						if possibleConstructor == int32(mtproto.CRC32_langpack_getLanguages_800fd57d) {
							fmt.Printf("  Found langpack_getLanguages!\n")
							return &mtproto.TLLangpackGetLanguages{}
						}
					}
				}
			}
		}
	}
	
	return nil
}

func min(a, b int) int {
	if a < b { return a }
	return b
}

func (cp *ConnProp) processAcknowledgment(serverMsg *ServerMessage, salt, sessionId int64) {
	clientReqId := serverMsg.clientRequestId
	currentState := cp.requestState[clientReqId]
	queryType := cp.clientRequests[clientReqId]
	
	fmt.Printf("DEBUG: ack for msgId=%d, type=%s, state=%s, query=%s\n", serverMsg.msgId, serverMsg.msgType, currentState, queryType)
	
	if serverMsg.msgType == "new_session" {
		if currentState == "session_sent" {
			// First acknowledgment - client wants to see new_session again
			msgCounter++
			fmt.Printf("<-- %03d_received_data.bin\n", msgCounter)
			fmt.Printf("MsgId: %d\n", serverMsg.msgId)
			fmt.Printf("Offset 84: data2:{predicate_name:\"new_session_created\"  constructor:CRC32_new_session_created  first_msg_id:%d}\n\n", clientReqId)
			
			// Resend the same new_session_created message
			cp.sendWithMsgId(serverMsg.content, salt, sessionId, serverMsg.msgId)
			cp.requestState[clientReqId] = "session_acked_once"
			
		} else if currentState == "session_acked_once" {
			// Second acknowledgment - now send the rpc_result based on the actual query
			msgCounter++
			fmt.Printf("<-- %03d_received_data.bin\n", msgCounter)
			rpcMsgId := mtproto.GenerateMessageId()
			fmt.Printf("MsgId: %d\n", rpcMsgId)
			fmt.Printf("Offset 72: {rpc_result#f35c6d01: req_msg_id: %d, result: %%!s(<nil>)}\n\n", clientReqId)
			
			// Generate RPC response based on query type
			rpcBuf := cp.generateRpcResponse(clientReqId, queryType)
			
			// Track the rpc_result message
			cp.serverMessages[rpcMsgId] = &ServerMessage{
				msgId: rpcMsgId,
				msgType: "rpc_result", 
				clientRequestId: clientReqId,
				acknowledged: false,
				content: rpcBuf,
			}
			
			cp.sendWithMsgId(rpcBuf, salt, sessionId, rpcMsgId)
			cp.requestState[clientReqId] = "rpc_sent"
		}
	} else if serverMsg.msgType == "rpc_result" && currentState == "rpc_sent" {
		// RPC result acknowledged - request completed
		cp.requestState[clientReqId] = "completed"
	}
}

func (cp *ConnProp) generateRpcResponse(clientReqId int64, queryType string) []byte {
	rpcBuf := mtproto.NewEncodeBuf(512)
	rpcBuf.Int(-212046591); rpcBuf.Long(clientReqId)
	
	// Generate response based on the actual query type
	switch queryType {
	case "*mtproto.TLLangpackGetLanguages":
		// Return empty/nil result for langpack_getLanguages (not implemented)
		rpcBuf.Bytes(make([]byte, 4))
	case "*mtproto.TLHelpGetNearestDc":
		// Return a TLNearestDc response
		rpcBuf.Int(-1910892651) // 0x8e1a1775 as signed int32
		rpcBuf.String("US")     // country
		rpcBuf.Int(2)           // this_dc
		rpcBuf.Int(2)           // nearest_dc
	default:
		// Default: return nil result
		rpcBuf.Bytes(make([]byte, 4))
	}
	
	return rpcBuf.GetBuf()
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