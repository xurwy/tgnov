package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/kr/pretty"
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/proto/mtproto/crypto"
)

var (
	DEBUG_LVL = func() int {
		if v := os.Getenv("DEBUG_LVL"); v != "" {
			if l, _ := strconv.Atoi(v); l > 0 {
				return l
			}
		}
		return 1
	}()
	ctrIsInitialized int
	pendingRequests  = make(map[int64]string)
)

func logf(level int, format string, args ...interface{}) {
	if level <= DEBUG_LVL {
		log.Printf("[%d] "+format, append([]interface{}{level}, args...)...)
	}
}

type ConnProp struct {
	conn net.Conn
	cryp *AesCTR128Crypto
}

func handleAuthenticatedMessage(cp *ConnProp, buff []byte, n int) {
	if !readAuthKey() || crAuthKey == nil {
		return
	}
	decrypted := cp.cryp.Decrypt(buff[:n])
	for offset := 0; offset <= len(decrypted)-32; offset++ {
		if offset+16 > len(decrypted) {
			break
		}
		msgKey := decrypted[offset : offset+16]
		if offset+16 >= len(decrypted) {
			continue
		}
		encData := padTo16(decrypted[offset+16:])

		func() {
			defer func() {
				if r := recover(); r != nil {
					logf(2, "Decrypt failed at offset %d: %v", offset, r)
				}
			}()
			if rawP, err := crAuthKey.AesIgeDecrypt(msgKey, encData); err == nil && len(rawP) >= 24 {
				salt, sessionId, msgId := int64(binary.LittleEndian.Uint64(rawP[0:8])), int64(binary.LittleEndian.Uint64(rawP[8:16])), int64(binary.LittleEndian.Uint64(rawP[16:24]))
				if o := bytesToTL2(rawP[16:]).Object; o != nil {
					logf(1, "Received %T", o)
					if _, isAck := o.(*mtproto.TLMsgsAck); !isAck {
						pendingRequests[msgId] = fmt.Sprintf("%T", o)
						cp.replyMsg(o, msgId, salt, sessionId)
					}
				}
			}
		}()
	}
}
func handleConnection(conn net.Conn) {
	defer conn.Close()
	connection = conn
	cp := &ConnProp{conn: conn}
	ctrIsInitialized = 0
	var Nonce, ServerNonce, newNonce, A []byte
	dhOk := false

	for {
		buffer := make([]byte, 1024)
		n, _ := conn.Read(buffer)
		if n == 0 {
			break
		}
		if ctrIsInitialized == 0 {
			cp.cryp = initializeCTRCodec(buffer, n)
			ctrIsInitialized = 1
		}
		if !dhOk {
			decrypted := cryptoCodec.Decrypt(buffer[:n])
			for _, offset := range []int{32, 50, 64, 73} {
				if _, obj, _ := parseFromIncomingMessage(decrypted[offset:]); obj != nil {
					logf(2, "%# v", pretty.Formatter(obj))
					switch obj.(type) {
					case *mtproto.TLReqPqMulti:
						conn.Write(cp.pack(handleReqPqMulti(obj)))
					case *mtproto.TLReq_DHParams:
						Nonce, ServerNonce, newNonce, A, _ = handleReqDHParams(cp, obj)
					case *mtproto.TLSetClient_DHParams:
						handleSetClientDHParams(cp, obj, Nonce, ServerNonce, newNonce, A)
						dhOk = true
					}
					break
				}
			}
		} else {
			handleAuthenticatedMessage(cp, buffer, n)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
func readAuthKey() bool {
	if authKey, err := os.ReadFile("auth_key.bin"); err == nil && len(authKey) == 256 && !bytes.Equal(authKey, make([]byte, 256)) {
		sha1Hash := sha1.Sum(authKey)
		crAuthKey = crypto.NewAuthKey(int64(binary.LittleEndian.Uint64(sha1Hash[12:20])), authKey)
		return true
	}
	return false
}
func (cp *ConnProp) encode2(data []byte) []byte {
	size := len(data) / 4
	sb := []byte{byte(size)}
	if size >= 127 {
		sb = make([]byte, 4)
		binary.LittleEndian.PutUint32(sb, uint32(size<<8|127))
	}
	return cp.cryp.Encrypt(append(sb, data...))
}

func (cp *ConnProp) pack(obj mtproto.TLObject) []byte {
	x := mtproto.NewEncodeBuf(512)
	serializeToBuffer(x, mtproto.GenerateMessageId(), obj)
	return cp.encode2(x.GetBuf())
}

func (cp *ConnProp) sendTLObjectResponse(obj mtproto.TLObject) {
	x := mtproto.NewEncodeBuf(512)
	serializeToBuffer(x, mtproto.GenerateMessageId(), obj)
	cp.conn.Write(cp.encode2(x.GetBuf()))
}

func (cp *ConnProp) sendEncryptedMessage(messageBody []byte, salt, sessionId, requestMsgId int64, responseType string) {
	if crAuthKey == nil {
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
	cp.conn.Write(cp.encode2(x.GetBuf()))
	if requestMsgId != 0 {
		delete(pendingRequests, requestMsgId)
		logf(1, "Sent %s response to %d", responseType, requestMsgId)
	}
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
func (cp *ConnProp) replyMsg(o mtproto.TLObject, msgId, salt, sessionId int64) {
	buf := mtproto.NewEncodeBuf(512)
	buf.Int(-212046591)
	buf.Long(msgId)
	switch obj := o.(type) {
	case *mtproto.TLHelpGetConfig, *mtproto.TLInvokeWithLayer:
		cp.sendEncryptedMessage(GetConfigRpcResult(msgId), salt, sessionId, msgId, "Config")
		return
	case *mtproto.TLAuthBindTempAuthKey:
		buf.Int(-1720552011)
		cp.sendEncryptedMessage(buf.GetBuf(), salt, sessionId, msgId, "AuthBind")
		s := mtproto.NewEncodeBuf(512)
		(&mtproto.TLNewSessionCreated{Data2: &mtproto.NewSession{PredicateName: "new_session_created", Constructor: -1631450872, FirstMsgId: 7523238081306948616, UniqueId: 7469723214292374799, ServerSalt: -4468521727382002472}}).Encode(s, 0)
		cp.sendEncryptedMessage(s.GetBuf(), salt, sessionId, 0, "")
		return
	case *mtproto.TLPingDelayDisconnect:
		pongData := mtproto.NewEncodeBuf(88)
		pongData.Int(0x347773c5)
		pongData.Long(msgId)
		pongData.Long(obj.PingId)
		cp.sendEncryptedMessage(pongData.GetBuf(), salt, sessionId, msgId, "PingDelayDisconnect") // 0x347773c5 = 880243653
		return
	case *mtproto.TLDestroySession:
		buf.Int(-501201412)
		buf.Long(obj.SessionId)
	case *mtproto.TLMsgContainer:
		for _, m := range obj.Messages {
			cp.replyMsg(m.Object, m.MsgId, salt, sessionId)
		}
		return
	default:
		if _, isAck := o.(*mtproto.TLMsgsAck); !isAck {
			delete(pendingRequests, msgId)
			logf(1, "Unhandled: %T", o)
		}
		return
	}
	cp.sendEncryptedMessage(buf.GetBuf(), salt, sessionId, msgId, fmt.Sprintf("%T", o))
}

func main() {
	log.SetFlags(0)
	listener, _ := net.Listen("tcp", ":10443")
	defer listener.Close()
	log.Printf("Server listening on :10443")
	for i := 0; i < 10; i++ {
		if conn, err := listener.Accept(); err == nil {
			handleConnection(conn)
		}
	}
}
