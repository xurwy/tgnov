package main

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"time"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/proto/mtproto/crypto"
)

var ctr, ctrIsInitialized int
type ConnProp struct { 
	conn net.Conn
	cryp *AesCTR128Crypto
	sessionCreated map[int64]bool  // Track which msgIds have received session created
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	cp := &ConnProp{
		conn: conn,
		sessionCreated: make(map[int64]bool),
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
				decrypted := cp.cryp.Decrypt(buffer[:n])
				for offset := 0; offset <= len(decrypted)-32; offset++ {
					if offset+16 >= len(decrypted) { continue }
					func() {
						defer func() { recover() }()
						if rawP, err := crAuthKey.AesIgeDecrypt(decrypted[offset:offset+16], padTo16(decrypted[offset+16:])); err == nil && len(rawP) >= 24 {
							fmt.Println("aes err", err)
							salt, sessionId, msgId := int64(binary.LittleEndian.Uint64(rawP[0:8])), int64(binary.LittleEndian.Uint64(rawP[8:16])), int64(binary.LittleEndian.Uint64(rawP[16:24]))
							if o := bytesToTL2(rawP[16:]).Object; o != nil { 
								ctr++; cp.replyMsg(o, msgId, salt, sessionId) 
							}
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

func (cp *ConnProp) handleRPCQuery(query mtproto.TLObject, msgId int64) *mtproto.EncodeBuf {
	buf := mtproto.NewEncodeBuf(512)
	buf.Int(-212046591) // rpc_result constructor
	buf.Long(msgId)     // req_msg_id
	
	switch query.(type) {
	case *mtproto.TLLangpackGetLanguages:
		fmt.Println("Handling langpack.getLanguages")
		// Return empty languages vector
		buf.Int(481674261) // vector constructor
		buf.Int(0)           // count = 0
	case *mtproto.TLHelpGetNearestDc:
		fmt.Println("Handling help.getNearestDc")
		// nearestDc constructor: -1910892683
		buf.Int(-1910892683) // nearestDc
		buf.String("CN")     // country
		buf.Int(1)           // this_dc
		buf.Int(1)           // nearest_dc
	case *mtproto.TLHelpGetCountriesList:
		fmt.Println("Handling help.getCountriesList")
		// help.countriesList constructor: -2016381538
		buf.Int(-2016381538) // help.countriesList
		buf.Int(481674261)  // vector constructor for countries
		buf.Int(0)           // count = 0 (no countries)
		buf.Int(0)           // hash = 0
	default:
		// For unknown queries, send empty result
		buf.Int(481674261) // vector constructor
		buf.Int(0)           // count = 0
	}
	
	return buf
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
	case *mtproto.TLInvokeWithLayer:
		fmt.Printf("%d %# v\n", msgId, o)
		invLayer := o.(*mtproto.TLInvokeWithLayer)
		
		// Send NewSessionCreated ONCE if not already sent for this msgId
		if !cp.sessionCreated[msgId] {
			buf := mtproto.NewEncodeBuf(512)
			buf.Int(-1631450872); buf.Long(msgId); buf.Long(time.Now().UnixNano()); buf.Long(salt)
			cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
			cp.sessionCreated[msgId] = true
		}
		
		// Find the innermost query
		var query mtproto.TLObject
		for qBytes := invLayer.Query; len(qBytes) > 0; {
			qBuf := mtproto.NewDecodeBuf(qBytes)
			if qObj := qBuf.Object(); qObj != nil {
				query = qObj
				// Check for nested Query field
				v := reflect.ValueOf(qObj)
				if v.Kind() == reflect.Ptr { v = v.Elem() }
				if v.Kind() == reflect.Struct {
					if field := v.FieldByName("Query"); field.IsValid() && !field.IsNil() {
						if nextBytes, ok := field.Interface().([]byte); ok && len(nextBytes) > 0 {
							qBytes = nextBytes
							continue
						}
					}
				}
			}
			break
		}
		
		// Handle RPC query - send the result
		buf := cp.handleRPCQuery(query, msgId)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
		
	case *mtproto.TLAuthSendCode:
		fmt.Printf("%d TLAuthSendCode\n", msgId)
		authSendCode := o.(*mtproto.TLAuthSendCode)
		fmt.Printf("Phone: %s\n", authSendCode.PhoneNumber)
		
		// Send auth.sentCode result directly
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591)  // rpc_result constructor
		buf.Long(msgId)      // req_msg_id
		buf.Int(0x5e002502)  // auth.sentCode constructor (TL_auth_sentCode)
		
		// flags: bit 0 (type), bit 4 (timeout) = 0x11 = 17
		buf.Int(17)          // flags (has type and timeout only, no next_type)
		
		// type: auth.sentCodeTypeSms (correct constructor)
		buf.Int(-1073693790) // auth.sentCodeTypeSms constructor (0xc000bba2)
		buf.Int(5)           // length (SMS code length)
		
		// phone_code_hash
		buf.String("21e22a8d47e7fc8241239f6a0102786c")
		
		// timeout (optional, included because of flag bit 4)
		buf.Int(120)         // 120 seconds timeout
		
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
		
	case *mtproto.TLMsgContainer:
		for _, m := range obj.Messages { cp.replyMsg(m.Object, m.MsgId, salt, sessionId) }
	case *mtproto.TLLangpackGetLanguages, *mtproto.TLHelpGetNearestDc, *mtproto.TLHelpGetCountriesList:
		// Handle direct RPC queries (not wrapped in invokeWithLayer)
		fmt.Printf("Direct RPC query: %T\n", o)
		buf := cp.handleRPCQuery(o, msgId)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	default:
		// Check if it's any other RPC query that should be handled
		fmt.Printf("Unknown message type: %T\n", o)
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