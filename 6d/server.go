package main

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/proto/mtproto/crypto"
)

type ConnProp struct { 
	conn net.Conn
	aesCtr *AesCTR128Crypto
	ctrInitialized bool
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	cp := &ConnProp{conn: conn}
	// loadAuthKey()

	var nonce, serverNonce, newNonce, a []byte
	buffer := make([]byte, 5000)

	for {
		n, err := conn.Read(buffer)
		if n == 0 { break }
		logf(1, "Read %d bytes\n", n)
		fmt.Println(err)

		if !cp.ctrInitialized {
			cp.aesCtr = initializeCTRCodec(buffer, n)
			cp.ctrInitialized = true
		}

		decrypted := cp.aesCtr.Decrypt(buffer[:n])

		if hasAuthKeyId(decrypted) {
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
			logf(1, "Handshake: %T at offset %d\n", obj, offset)
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
	if len(decrypted) < 32 { return }
	if cp.aesIgeDecrypt(decrypted, 0) { return }
	for offset := 1; offset <= len(decrypted)-32; offset++ {
		if cp.aesIgeDecrypt(decrypted, offset) { return }
	}
	logf(1, "No valid message found\n")
}

func (cp *ConnProp) aesIgeDecrypt(decrypted []byte, offset int) bool {
	if offset+16 >= len(decrypted) { return false }

	rawP, err := crAuthKey.AesIgeDecrypt(decrypted[offset:offset+16], decrypted[offset+16:])
	if err != nil || len(rawP) < 24 { return false }

	msg := &mtproto.TLMessage2{}
	msg.Decode(mtproto.NewDecodeBuf(rawP[16:]))
	if msg.Object == nil { return false }

	salt := int64(binary.LittleEndian.Uint64(rawP[0:8]))
	sessionId := int64(binary.LittleEndian.Uint64(rawP[8:16]))
	msgId := int64(binary.LittleEndian.Uint64(rawP[16:24]))

	logf(1, "Message: %T at offset %d, msgId: %d\n", msg.Object, offset, msgId)
	cp.replyMsg(msg.Object, msgId, salt, sessionId)
	return true
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
	if crAuthKey == nil { return }
	x := mtproto.NewEncodeBuf(512)
	x.Long(salt); x.Long(sessionId); x.Long(mtproto.GenerateMessageId())
	x.Int(1); x.Int(int32(len(body))); x.Bytes(body)
	msgKey, data, _ := crAuthKey.AesIgeEncrypt(x.GetBuf())
	x2 := mtproto.NewEncodeBuf(8 + len(msgKey) + len(data))
	x2.Long(crAuthKey.AuthKeyId()); x2.Bytes(msgKey); x2.Bytes(data)
	cp.conn.Write(cp.encodeCtr(x2.GetBuf()))
}

func loadAuthKey() {
	if authKey, _ := os.ReadFile("auth_key.bin"); len(authKey) == 256 {
		sha1Hash := sha1.Sum(authKey)
		crAuthKey = crypto.NewAuthKey(int64(binary.LittleEndian.Uint64(sha1Hash[12:20])), authKey)
		logf(1, "Auth key loaded: %d\n", crAuthKey.AuthKeyId())
	}
}

func hasAuthKeyId(data []byte) bool {
	if crAuthKey == nil || len(data) < 8 { return false }
	target := crAuthKey.AuthKeyId()
	for i := 0; i <= len(data)-8; i++ {
		if int64(binary.LittleEndian.Uint64(data[i:i+8])) == target {
			logf(1, "AuthKeyId found at offset %d\n", i)
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
	listener, _ := net.Listen("tcp", ":10443")
	defer listener.Close()
	log.Printf("Server listening on :10443")
	for i := 0; i < 50; i++ {
		if conn, err := listener.Accept(); err == nil {
			handleConnection(conn)
		}
	}
}