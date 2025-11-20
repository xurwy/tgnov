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
	sessionCreated map[int64]bool
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
					decrypted := cp.cryp.Decrypt(buffer[:n])
				for offset := 0; offset <= len(decrypted)-32; offset++ {
					if offset+16 >= len(decrypted) { continue }
					func() {
						defer func() { recover() }()
						if rawP, err := crAuthKey.AesIgeDecrypt(decrypted[offset:offset+16], padTo16(decrypted[offset+16:])); err == nil && len(rawP) >= 24 {
								salt, sessionId, msgId := int64(binary.LittleEndian.Uint64(rawP[0:8])), int64(binary.LittleEndian.Uint64(rawP[8:16])), int64(binary.LittleEndian.Uint64(rawP[16:24]))
							if o := bytesToTL2(rawP[16:]).Object; o != nil { ctr++; cp.replyMsg(o, msgId, salt, sessionId) }
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
	buf.Int(-212046591)
	buf.Long(msgId)
	
	switch query.(type) {
	case *mtproto.TLLangpackGetLanguages:
		buf.Int(481674261); buf.Int(62)
	case *mtproto.TLHelpGetNearestDc:
		buf.Int(-1910892683); buf.String("CN"); buf.Int(1); buf.Int(1)
	case *mtproto.TLHelpGetCountriesList:
		buf.Int(-2016381538); buf.Int(481674261); buf.Int(0); buf.Int(0)
	default:
		buf.Int(481674261); buf.Int(0)
	}
	
	return buf
}

func (cp *ConnProp) replyMsg(o mtproto.TLObject, msgId, salt, sessionId int64) {
	switch obj := o.(type) {
	case *mtproto.TLPingDelayDisconnect:
		buf := mtproto.NewEncodeBuf(88)
		buf.Int(0x347773c5); buf.Long(msgId); buf.Long(obj.PingId)
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
	case *mtproto.TLDestroySession:
		destroyData := mtproto.NewEncodeBuf(8); destroyData.Long(obj.SessionId)
		buf := mtproto.NewEncodeBuf(32)
		buf.Int(-212046591); buf.Long(msgId); buf.Int(-501201412); buf.Bytes(destroyData.GetBuf())
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
	case *mtproto.TLInvokeWithLayer:
		invLayer := o.(*mtproto.TLInvokeWithLayer)
		if !cp.sessionCreated[msgId] {
			buf := mtproto.NewEncodeBuf(512)
			buf.Int(-1631450872); buf.Long(msgId); buf.Long(time.Now().UnixNano()); buf.Long(salt)
			cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
			cp.sessionCreated[msgId] = true
		}
		var query mtproto.TLObject
		for qBytes := invLayer.Query; len(qBytes) > 0; {
			qBuf := mtproto.NewDecodeBuf(qBytes)
			if qObj := qBuf.Object(); qObj != nil {
				query = qObj
				v := reflect.ValueOf(qObj)
				if v.Kind() == reflect.Ptr { v = v.Elem() }
				if v.Kind() == reflect.Struct {
					if field := v.FieldByName("Query"); field.IsValid() && !field.IsNil() {
						if nextBytes, ok := field.Interface().([]byte); ok && len(nextBytes) > 0 { qBytes = nextBytes; continue }
					}
				}
			}
			break
		}
		buf := cp.handleRPCQuery(query, msgId)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
		
	case *mtproto.TLAuthSendCode:
		fmt.Printf("%d TLAuthSendCode Phone: %s\n", msgId, o.(*mtproto.TLAuthSendCode).PhoneNumber)
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591); buf.Long(msgId); buf.Int(0x5e002502); buf.Int(17)
		buf.Int(-1073693790); buf.Int(5); buf.String("21e22a8d47e7fc8241239f6a0102786c"); buf.Int(120)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLMsgContainer:
		for _, m := range obj.Messages { cp.replyMsg(m.Object, m.MsgId, salt, sessionId) }
	case *mtproto.TLAuthSignIn:
		fmt.Printf("%d TLAuthSignIn Phone: %s, Code: %s\n", msgId, o.(*mtproto.TLAuthSignIn).PhoneNumber, o.(*mtproto.TLAuthSignIn).PhoneCode_FLAGSTRING.Value)
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591); buf.Long(msgId); buf.Int(1148485274); buf.Int(0)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLAuthSignUp:
		authSignUp := o.(*mtproto.TLAuthSignUp)
		fmt.Printf("%d TLAuthSignUp Phone: %s, Name: %s %s\n", msgId, authSignUp.PhoneNumber, authSignUp.FirstName, authSignUp.LastName)
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591); buf.Long(msgId); buf.Int(782418132); buf.Int(0); buf.Int(-742634630)
		buf.Int(int32(0x400 | 0x800 | 0x1000 | 0x1 | 0x2 | 0x4 | 0x10 | 0x40))
		buf.Long(12345); buf.Long(12345678)
		buf.String(authSignUp.FirstName); buf.String(authSignUp.LastName); buf.String(authSignUp.PhoneNumber)
		buf.Int(-496024847)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLHelpGetPromoData:
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591); buf.Long(msgId); buf.Int(-1728664459); buf.Int(int32(time.Now().Unix() + 3600))
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLAccountUpdateStatus:
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591); buf.Long(msgId); buf.Int(-1720552011)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLLangpackGetLanguages, *mtproto.TLHelpGetNearestDc, *mtproto.TLHelpGetCountriesList:
		buf := cp.handleRPCQuery(o, msgId)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
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