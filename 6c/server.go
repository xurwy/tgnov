package main

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/proto/mtproto/crypto"
)

type ConnProp struct { 
	conn net.Conn
	cryp *AesCTR128Crypto
	ctrInitialized bool
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	cp := &ConnProp{
		conn: conn,
	}
	var Nonce, ServerNonce, newNonce, A []byte
	dhOk := false
	for {
		buffer := make([]byte, 5000)
		if n, err := conn.Read(buffer); n == 0 { break } else {
			logf(1, "(%d) %02x\n", n, buffer[:10])
			fmt.Println(err)
			if authKey, _ := os.ReadFile("auth_key.bin"); len(authKey) == 256 {
				sha1Hash := sha1.Sum(authKey)
				crAuthKey = crypto.NewAuthKey(int64(binary.LittleEndian.Uint64(sha1Hash[12:20])), authKey)
				dhOk = true
			}
			if !cp.ctrInitialized { cp.cryp = initializeCTRCodec(buffer, n); cp.ctrInitialized = true }
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
				decrypted := cp.cryp.Decrypt(buffer[:n])
				messageFound := false
				for offset := 0; offset <= len(decrypted)-32; offset++ {
					if offset+16 >= len(decrypted) { continue }
					func() {
						defer func() { recover() }()
						if rawP, err := crAuthKey.AesIgeDecrypt(decrypted[offset:offset+16], padTo16(decrypted[offset+16:])); err == nil && len(rawP) >= 24 {
							salt, sessionId, msgId := int64(binary.LittleEndian.Uint64(rawP[0:8])), int64(binary.LittleEndian.Uint64(rawP[8:16])), int64(binary.LittleEndian.Uint64(rawP[16:24]))
							if msg := bytesToTL2(rawP[16:]); msg.Object != nil { 
								messageFound = true
								sobj := fmt.Sprintf("%T", msg.Object) // *mtproto.TL
								sobj = CamelToUnderscore(sobj[9:]) // tl_a_b
								sobj = makeTLTable(sobj)
								logf(1, "Found at offset %d: %s, msgId: %d\n", offset, sobj, msgId)
								cp.replyMsg(msg.Object, msgId, salt, sessionId) 
							}
						}
					}()
				}
				if !messageFound {
					logf(1, "No message found in %d bytes of decrypted data\n", len(decrypted))
				}
			}
		}
		// time.Sleep(500 * time.Millisecond)
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

func (cp *ConnProp) send(body []byte, salt, sessionId int64) {
	if crAuthKey == nil { return }
	x := mtproto.NewEncodeBuf(512)
	x.Long(salt); x.Long(sessionId); x.Long(mtproto.GenerateMessageId())
	x.Int(1); x.Int(int32(len(body))); x.Bytes(body)
	msgKey, data, _ := crAuthKey.AesIgeEncrypt(x.GetBuf())
	x2 := mtproto.NewEncodeBuf(8 + len(msgKey) + len(data))
	x2.Long(crAuthKey.AuthKeyId()); x2.Bytes(msgKey); x2.Bytes(data)
	
	cp.conn.Write(cp.encode_ctr(x2.GetBuf()))
}

func bytesToTL2(b []byte) *mtproto.TLMessage2 { msg := &mtproto.TLMessage2{}; msg.Decode(mtproto.NewDecodeBuf(b)); return msg }
func padTo16(data []byte) []byte { if rem := len(data) % 16; rem != 0 { data = append(data, make([]byte, 16-rem)...) }; return data }

/*
func createUserFullResponse(msgId int64) []byte {
	buf := mtproto.NewEncodeBuf(1024)
	
	// rpc_result constructor
	buf.Int(-212046591) // 0xf35c6d01
	buf.Long(msgId)
	
	// users.userFull#3b6d152e constructor
	buf.Int(0x3b6d152e) // 997004590 as unsigned, or use buf.Int(997004590)
	
	// UserFull object - userFull#979d2376
	buf.Int(-1745552522) // -1745552522 as signed int32, but better as hex
	
	buf.Int(128) // flags (bit 7 set for can_pin_message)
	buf.Int(0) // flags2
	
	buf.Long(777010)
	buf.Int(-1388545662) // -1388545662 as signed
	buf.Int(0)          // flags for peerSettings
	
	// notify_settings - PeerNotifySettings (always required)
	// peerNotifySettings#99622c0c
	buf.Int(-1721619444) // -1721619444 as signed
	buf.Int(0)          // flags for notify_settings
	
	// common_chats_count (always present)
	buf.Int(0)
	
	// chats - Vector<Chat> (always required)
	buf.Int(0x1cb5c415) // vector constructor
	buf.Int(0)          // empty vector
	
	// users - Vector<User> (always required)
	buf.Int(0x1cb5c415) // vector constructor
	buf.Int(1)          // one user
	
	// User object - user#20b1422 (hex of decimal 34267170)
	buf.Int(0x20b1422)  // or buf.Int(34267170)
	
	// User flags
	buf.Int(7255)       // flags (bits: 0,1,2,10,11,12)
	buf.Int(0)          // flags2
	
	// id (always present)
	buf.Long(777010)
	
	// access_hash - flags.0 is set (7255 & 1 = 1)
	buf.Long(9110083885959396583)
	
	// first_name - flags.1 is set (7255 & 2 = 2)
	buf.String("Y")
	
	// last_name - flags.2 is set (7255 & 4 = 4)
	buf.String("Y")
	
	// status - flags.6 is set
	// userStatusOffline#8c703f
	buf.Int(0x8c703f)   // 9203071 as signed int
	buf.Int(0)          // was_online
	
	return buf.GetBuf()
}
*/

func main() {
	log.SetFlags(0)
	listener, _ := net.Listen("tcp", ":10443")
	defer listener.Close()
	log.Printf("Server listening on :10443")
	for i := 0; i < 50; i++ { if conn, err := listener.Accept(); err == nil { handleConnection(conn) } }
}

func CamelToUnderscore(s string) string {
	re1 := regexp.MustCompile("([a-z0-9])([A-Z])")
	re2 := regexp.MustCompile("([A-Z]+)([A-Z][a-z])")
	s = re1.ReplaceAllString(s, "${1}_${2}")
	s = re2.ReplaceAllString(s, "${1}_${2}")
	return strings.ToLower(s)
}

func makeTLTable(serverFormat string) string {
	// Remove tl_ prefix
	if strings.HasPrefix(serverFormat, "tl_") {
		serverFormat = serverFormat[3:]
	}
	
	// Split by underscore
	parts := strings.Split(serverFormat, "_")
	
	// Build client format
	if len(parts) < 2 {
		return "TL_" + serverFormat
	}
	
	// First part is namespace (auth, users, messages, etc)
	namespace := parts[0]
	
	// Rest is camelCased
	var methodParts []string
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) > 0 {
			if i == 1 {
				// First word of method stays lowercase
				methodParts = append(methodParts, parts[i])
			} else {
				// Capitalize first letter
				methodParts = append(methodParts, strings.Title(parts[i]))
			}
		}
	}
	
	clientFormat := "TL_" + namespace + "_" + strings.Join(methodParts, "")
	
	return clientFormat
}