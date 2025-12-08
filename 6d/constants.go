package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/teamgram/marmota/pkg/hack"
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/proto/mtproto/crypto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	dh2048P                        = []byte{0xc7, 0x1c, 0xae, 0xb9, 0xc6, 0xb1, 0xc9, 0x04, 0x8e, 0x6c, 0x52, 0x2f, 0x70, 0xf1, 0x3f, 0x73, 0x98, 0x0d, 0x40, 0x23, 0x8e, 0x3e, 0x21, 0xc1, 0x49, 0x34, 0xd0, 0x37, 0x56, 0x3d, 0x93, 0x0f, 0x48, 0x19, 0x8a, 0x0a, 0xa7, 0xc1, 0x40, 0x58, 0x22, 0x94, 0x93, 0xd2, 0x25, 0x30, 0xf4, 0xdb, 0xfa, 0x33, 0x6f, 0x6e, 0x0a, 0xc9, 0x25, 0x13, 0x95, 0x43, 0xae, 0xd4, 0x4c, 0xce, 0x7c, 0x37, 0x20, 0xfd, 0x51, 0xf6, 0x94, 0x58, 0x70, 0x5a, 0xc6, 0x8c, 0xd4, 0xfe, 0x6b, 0x6b, 0x13, 0xab, 0xdc, 0x97, 0x46, 0x51, 0x29, 0x69, 0x32, 0x84, 0x54, 0xf1, 0x8f, 0xaf, 0x8c, 0x59, 0x5f, 0x64, 0x24, 0x77, 0xfe, 0x96, 0xbb, 0x2a, 0x94, 0x1d, 0x5b, 0xcd, 0x1d, 0x4a, 0xc8, 0xcc, 0x49, 0x88, 0x07, 0x08, 0xfa, 0x9b, 0x37, 0x8e, 0x3c, 0x4f, 0x3a, 0x90, 0x60, 0xbe, 0xe6, 0x7c, 0xf9, 0xa4, 0xa4, 0xa6, 0x95, 0x81, 0x10, 0x51, 0x90, 0x7e, 0x16, 0x27, 0x53, 0xb5, 0x6b, 0x0f, 0x6b, 0x41, 0x0d, 0xba, 0x74, 0xd8, 0xa8, 0x4b, 0x2a, 0x14, 0xb3, 0x14, 0x4e, 0x0e, 0xf1, 0x28, 0x47, 0x54, 0xfd, 0x17, 0xed, 0x95, 0x0d, 0x59, 0x65, 0xb4, 0xb9, 0xdd, 0x46, 0x58, 0x2d, 0xb1, 0x17, 0x8d, 0x16, 0x9c, 0x6b, 0xc4, 0x65, 0xb0, 0xd6, 0xff, 0x9c, 0xa3, 0x92, 0x8f, 0xef, 0x5b, 0x9a, 0xe4, 0xe4, 0x18, 0xfc, 0x15, 0xe8, 0x3e, 0xbe, 0xa0, 0xf8, 0x7f, 0xa9, 0xff, 0x5e, 0xed, 0x70, 0x05, 0x0d, 0xed, 0x28, 0x49, 0xf4, 0x7b, 0xf9, 0x59, 0xd9, 0x56, 0x85, 0x0c, 0xe9, 0x29, 0x85, 0x1f, 0x0d, 0x81, 0x15, 0xf6, 0x35, 0xb1, 0x05, 0xee, 0x2e, 0x4e, 0x15, 0xd0, 0x4b, 0x24, 0x54, 0xbf, 0x6f, 0x4f, 0xad, 0xf0, 0x34, 0xb1, 0x04, 0x03, 0x11, 0x9c, 0xd8, 0xe3, 0xb9, 0x2f, 0xcc, 0x5b}
	dh2048G                        = []byte{0x03}
	zeroIV                         = make([]byte, 32)
	gBigIntDH2048P, gBigIntDH2048G = new(big.Int).SetBytes(dh2048P), new(big.Int).SetBytes(dh2048G)
)

const expiresTimeout = 3600

type AesCTR128Crypto struct{ decrypt, encrypt *crypto.AesCTR128Encrypt }

func newAesCTR128Crypto(d, e *crypto.AesCTR128Encrypt) *AesCTR128Crypto { return &AesCTR128Crypto{d, e} }
func (e *AesCTR128Crypto) Encrypt(plaintext []byte) []byte {
	if e == nil { log.Println("Encrypt Called"); return plaintext }
	return e.encrypt.Encrypt(plaintext)
}
func (e *AesCTR128Crypto) Decrypt(ciphertext []byte) []byte {
	if e == nil || e.decrypt == nil { fmt.Printf("ctr decrypt err %02x\n", ciphertext[:10]); return ciphertext }
	return e.decrypt.Encrypt(ciphertext)
}

func parseFromIncomingMessage(b []byte) (msgId int64, obj mtproto.TLObject, err error) {
	dBuf := mtproto.NewDecodeBuf(b)
	msgId = dBuf.Long()
	_ = dBuf.Int()
	obj = dBuf.Object()
	err = dBuf.GetError()
	return
}

func serializeToBuffer(x *mtproto.EncodeBuf, msgId int64, obj mtproto.TLObject) error {
	x.Long(0)
	x.Long(msgId)
	offset := x.GetOffset()
	x.Int(0)
	if err := obj.Encode(x, 0); err != nil { return err }
	x.IntOffset(offset, int32(x.GetOffset()-offset-4))
	return nil
}

func (cp *ConnProp) sendHandshakeRes(obj mtproto.TLObject) { cp.conn.Write(cp.encode(obj)) }

var (
	cryptoCodec *AesCTR128Crypto
)

func initializeCTRCodec(buffer []byte, n int) *AesCTR128Crypto {
	encrypted := buffer[:n]
	obfuscatedBuf := encrypted[:64]
	var tmp [64]byte
	for i := 0; i < 48; i++ { tmp[i] = obfuscatedBuf[55-i] }
	encryptor, _ := crypto.NewAesCTR128Encrypt(tmp[:32], tmp[32:48])
	decryptor, _ := crypto.NewAesCTR128Encrypt(obfuscatedBuf[8:40], obfuscatedBuf[40:56])
	cryptoCodec = newAesCTR128Crypto(decryptor, encryptor)
	return cryptoCodec
}

func handleReqDHParams(cp *ConnProp, obj mtproto.TLObject) ([]byte, []byte, []byte, []byte, error) {
	reqDhParam, _ := obj.(*mtproto.TLReq_DHParams)
	rsa, _ := crypto.NewRSACryptor("./server_pkcs1.key")
	innerData := rsa.Decrypt([]byte(reqDhParam.EncryptedData))
	key := innerData[:32]
	hash := crypto.Sha256Digest(innerData[32:])
	for i := 0; i < 32; i++ { key[i] = key[i] ^ hash[i] }
	hashPadded, _ := crypto.NewAES256IGECryptor(key, zeroIV).Decrypt(innerData[32:])
	for i, j := 0, 191; i < j; i, j = i+1, j-1 { hashPadded[i], hashPadded[j] = hashPadded[j], hashPadded[i] }
	dbuf := mtproto.NewDecodeBuf(hashPadded)
	o := dbuf.Object()
	var (
		handshakeType int
		expiresIn     int32
		pqInnerData   *mtproto.P_QInnerData
	)
	switch innerData := o.(type) {
	case *mtproto.TLPQInnerData:
		handshakeType = mtproto.AuthKeyTypePerm
		pqInnerData = innerData.To_P_QInnerData()
	case *mtproto.TLPQInnerDataDc:
		handshakeType = mtproto.AuthKeyTypePerm
		pqInnerData = innerData.To_P_QInnerData()
	case *mtproto.TLPQInnerDataTemp:
		handshakeType = mtproto.AuthKeyTypeTemp
		expiresIn = innerData.GetExpiresIn()
		pqInnerData = innerData.To_P_QInnerData()
	case *mtproto.TLPQInnerDataTempDc:
		if innerData.GetDc() < 0 {
			handshakeType = mtproto.AuthKeyTypeMediaTemp
		} else {
			handshakeType = mtproto.AuthKeyTypeTemp
		}
		expiresIn = innerData.GetExpiresIn()
		pqInnerData = innerData.To_P_QInnerData()
	default:
		return nil, nil, nil, nil, fmt.Errorf("onReq_DHParams - decode P_Q_inner_data error")
	}
	newNonce := pqInnerData.GetNewNonce()
	A := crypto.GenerateNonce(256)
	bigIntA := new(big.Int).SetBytes(A)
	gA := new(big.Int).Exp(gBigIntDH2048G, bigIntA, gBigIntDH2048P)
	serverDHInnerData := &mtproto.TLServer_DHInnerData{Data2: &mtproto.Server_DHInnerData{Constructor: mtproto.TLConstructor(mtproto.TLConstructor_CRC32_server_DH_inner_data), Nonce: reqDhParam.Nonce, ServerNonce: reqDhParam.ServerNonce, G: int32(dh2048G[0]), GA: string(gA.Bytes()), DhPrime: string(dh2048P), ServerTime: int32(time.Now().Unix())}}
	x := mtproto.NewEncodeBuf(512)
	serverDHInnerData.Encode(x, 0)
	serverDHInnerDataBuf := x.GetBuf()
	tmpAesKeyAndIV := make([]byte, 64)
	sha1A := sha1.Sum(append(newNonce, reqDhParam.ServerNonce...))
	sha1B := sha1.Sum(append(reqDhParam.ServerNonce, newNonce...))
	sha1C := sha1.Sum(append(newNonce, newNonce...))
	copy(tmpAesKeyAndIV, sha1A[:])
	copy(tmpAesKeyAndIV[20:], sha1B[:])
	copy(tmpAesKeyAndIV[40:], sha1C[:])
	copy(tmpAesKeyAndIV[60:], newNonce[:4])
	tmpLen := 20 + len(serverDHInnerDataBuf)
	if tmpLen%16 > 0 { tmpLen = (tmpLen/16 + 1) * 16 } else { tmpLen = 20 + len(serverDHInnerDataBuf) }
	tmpEncryptedAnswer := make([]byte, tmpLen)
	sha1Tmp := sha1.Sum(serverDHInnerDataBuf)
	copy(tmpEncryptedAnswer, sha1Tmp[:])
	copy(tmpEncryptedAnswer[20:], serverDHInnerDataBuf)
	e := crypto.NewAES256IGECryptor(tmpAesKeyAndIV[:32], tmpAesKeyAndIV[32:64])
	tmpEncryptedAnswer, _ = e.Encrypt(tmpEncryptedAnswer)
	serverDHParams := mtproto.MakeTLServer_DHParamsOk(&mtproto.Server_DH_Params{Constructor: mtproto.TLConstructor(mtproto.TLConstructor_CRC32_server_DH_params_ok), Nonce: reqDhParam.Nonce, ServerNonce: reqDhParam.ServerNonce, EncryptedAnswer: hack.String(tmpEncryptedAnswer)}).To_Server_DH_Params()
	_ = handshakeType
	_ = expiresIn
	cp.sendHandshakeRes(serverDHParams)
	return reqDhParam.Nonce, reqDhParam.ServerNonce, newNonce, A, nil
}

func handleSetClientDHParams(cp *ConnProp, obj mtproto.TLObject, nonce, serverNonce, newNonce, A []byte) error {
	setClientDHParams, _ := obj.(*mtproto.TLSetClient_DHParams)
	if !bytes.Equal(setClientDHParams.Nonce, nonce) { return fmt.Errorf("onSetClientDHParams - Wrong Nonce") }
	if !bytes.Equal(setClientDHParams.ServerNonce, serverNonce) { return fmt.Errorf("onSetClientDHParams - Wrong ServerNonce")}
	bEncryptedData := []byte(setClientDHParams.EncryptedData)
	tmpAesKeyAndIv := make([]byte, 64)
	sha1A := sha1.Sum(append(newNonce, serverNonce...))
	sha1B := sha1.Sum(append(serverNonce, newNonce...))
	sha1C := sha1.Sum(append(newNonce, newNonce...))
	copy(tmpAesKeyAndIv, sha1A[:])
	copy(tmpAesKeyAndIv[20:], sha1B[:])
	copy(tmpAesKeyAndIv[40:], sha1C[:])
	copy(tmpAesKeyAndIv[60:], newNonce[:4])
	d := crypto.NewAES256IGECryptor(tmpAesKeyAndIv[:32], tmpAesKeyAndIv[32:64])
	decryptedData, err := d.Decrypt(bEncryptedData)
	if err != nil { return fmt.Errorf("onSetClientDHParams - AES256IGECryptor decrypt error")}
	dBuf := mtproto.NewDecodeBuf(decryptedData[20:])
	clientDHInnerData := mtproto.MakeTLClient_DHInnerData(nil)
	clientDHInnerData.Data2.Constructor = mtproto.TLConstructor(dBuf.Int())
	err = clientDHInnerData.Decode(dBuf)
	if err != nil { log.Printf("onSetClientDHParams - TLClient_DHInnerData decode error: %s", err); return err }
	if !bytes.Equal(clientDHInnerData.GetNonce(), nonce) { return fmt.Errorf("onSetClientDHParams - Wrong client_DHInnerData's Nonce") }
	if !bytes.Equal(clientDHInnerData.GetServerNonce(), serverNonce) { return fmt.Errorf("onSetClientDHParams - Wrong client_DHInnerData's ServerNonce") }
	bigIntA := new(big.Int).SetBytes(A)
	authKeyNum := new(big.Int)
	authKeyNum.Exp(new(big.Int).SetBytes([]byte(clientDHInnerData.GetGB())), bigIntA, gBigIntDH2048P)
	authKey := make([]byte, 256)
	copy(authKey[256-len(authKeyNum.Bytes()):], authKeyNum.Bytes())
	authKeyAuxHash := make([]byte, len(newNonce))
	copy(authKeyAuxHash, newNonce)
	authKeyAuxHash = append(authKeyAuxHash, byte(0x01))
	sha1D := sha1.Sum(authKey)
	authKeyAuxHash = append(authKeyAuxHash, sha1D[:]...)
	sha1E := sha1.Sum(authKeyAuxHash[:len(authKeyAuxHash)-12])
	authKeyAuxHash = append(authKeyAuxHash, sha1E[:]...)
	authKeyId := int64(binary.LittleEndian.Uint64(authKeyAuxHash[len(newNonce)+1+12 : len(newNonce)+1+12+8]))

	// Save auth key to MongoDB
	cp.authKey = crypto.NewAuthKey(authKeyId, authKey)
	if err := SaveAuthKey(authKey, authKeyId); err != nil {
		log.Printf("[Conn %d] Failed to save auth key: %v\n", cp.connID, err)
	} else {
		log.Printf("[Conn %d] Auth key created and saved to MongoDB: %d\n", cp.connID, authKeyId)
	}

	dhGen := mtproto.MakeTLDhGenOk(&mtproto.SetClient_DHParamsAnswer{Nonce: nonce, ServerNonce: serverNonce, NewNonceHash1: calcNewNonceHash(newNonce, authKey, 0x01)}).To_SetClient_DHParamsAnswer()
	cp.sendHandshakeRes(dhGen)
	return nil
}

func handleReqPqMulti(obj mtproto.TLObject) mtproto.TLObject {
	reqPq, _ := obj.(*mtproto.TLReqPqMulti)
	var pq = string([]byte{0x17, 0xED, 0x48, 0x94, 0x1A, 0x08, 0xF9, 0x81})
	resPQ := mtproto.MakeTLResPQ(&mtproto.ResPQ{
		Nonce: reqPq.Nonce, 
		ServerNonce: crypto.GenerateNonce(16), 
		Pq: pq, 
		ServerPublicKeyFingerprints: []int64{-6205835210776354611},
	}).To_ResPQ()
	return resPQ
}

func calcNewNonceHash(newNonce, authKey []byte, b byte) []byte {
	authKeyAuxHash := make([]byte, len(newNonce))
	copy(authKeyAuxHash, newNonce)
	authKeyAuxHash = append(authKeyAuxHash, b)
	sha1D := sha1.Sum(authKey)
	authKeyAuxHash = append(authKeyAuxHash, sha1D[:]...)
	sha1E := sha1.Sum(authKeyAuxHash[:len(authKeyAuxHash)-12])
	authKeyAuxHash = append(authKeyAuxHash, sha1E[:]...)
	return authKeyAuxHash[len(authKeyAuxHash)-16:]
}

func GenerateAccessHash() int64 {
    var b [8]byte
    if _, err := rand.Read(b[:]); err != nil {
        panic(err)
    }
    return int64(binary.LittleEndian.Uint64(b[:]))
}

func gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func buildLangpackResponse() []byte {
	langBuf := mtproto.NewEncodeBuf(1024)
	langBuf.Int(481674261); langBuf.Int(3)
	langBuf.Int(-288727837); langBuf.Int(1); langBuf.String("English"); langBuf.String("en"); langBuf.String("English"); langBuf.String("en"); langBuf.Int(5744); langBuf.Int(5744); langBuf.String("https://translations.telegram.org/en/")
	langBuf.Int(-288727837); langBuf.Int(2); langBuf.String("Chinese (Simplified, @zh_CN)"); langBuf.String("classic-zh-cn"); langBuf.String("简体中文 (@zh_CN 版)"); langBuf.String("zh-hans-raw"); langBuf.String("zh"); langBuf.Int(5744); langBuf.Int(5744); langBuf.String("https://translations.telegram.org/classic-zh-cn/")
	langBuf.Int(-288727837); langBuf.Int(12); langBuf.String("Persian"); langBuf.String("fa-raw"); langBuf.String("فارسی (beta)"); langBuf.String("fa"); langBuf.Int(5744); langBuf.Int(5045); langBuf.String("https://translations.telegram.org/fa/")
	return langBuf.GetBuf()
}

func (cp *ConnProp) handleInvokeQuery(query mtproto.TLObject, msgId int64) *mtproto.EncodeBuf {

	qBuf := mtproto.NewDecodeBuf(query.(*mtproto.TLInitConnection).GetQuery())
	query = qBuf.Object()
	logf(1, "In query %T\n", query)
	return cp.overlapWithInvokeRes(query, msgId)
}

func (cp *ConnProp) overlapWithInvokeRes(query mtproto.TLObject, msgId int64) *mtproto.EncodeBuf {
	buf := mtproto.NewEncodeBuf(1024); buf.Int(-212046591); buf.Long(msgId)

	switch query.(type) {
	case *mtproto.TLLangpackGetLanguages:
		buf.Bytes(buildLangpackResponse())
	case *mtproto.TLHelpGetNearestDc:
		buf.Int(-1910892683); buf.String("CN"); buf.Int(1); buf.Int(1)
	case *mtproto.TLHelpGetCountriesList:
		help_countriesList.Encode(buf, 158)
	default:
		buf.Int(481674261); buf.Int(0) // empty vector
	}

	return buf
}

func (cp *ConnProp) encodeAndSend(obj mtproto.TLObject, msgId, salt, sessionId int64, bufSize int) {
	initialSize := 512
	if bufSize > 0 && bufSize < 2048 {
		initialSize = bufSize
	}
	buf := mtproto.NewEncodeBuf(initialSize)
	buf.Int(-212046591) // rpc_result
	buf.Long(msgId)
	obj.Encode(buf, 158)
	cp.send(buf.GetBuf(), salt, sessionId)
}

func (cp *ConnProp) replyMsg(o mtproto.TLObject, msgId, salt, sessionId int64) {
	switch obj := o.(type) {
	case *mtproto.TLPingDelayDisconnect:
		buf := mtproto.NewEncodeBuf(88)
		buf.Int(0x347773c5); buf.Long(msgId); buf.Long(obj.PingId)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLDestroySession:
		destroyData := mtproto.NewEncodeBuf(8); destroyData.Long(obj.SessionId)
		buf := mtproto.NewEncodeBuf(32)
		buf.Int(-212046591); buf.Long(msgId); buf.Int(-501201412); buf.Bytes(destroyData.GetBuf())
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLInvokeWithLayer:
		invLayer := o.(*mtproto.TLInvokeWithLayer)
		newSessionData := mtproto.NewEncodeBuf(512)
		newSessionData.Int(-1631450872); newSessionData.Long(msgId); newSessionData.Long(time.Now().UnixNano()); newSessionData.Long(salt)
		cp.send(newSessionData.GetBuf(), salt, sessionId)
		dBuf := mtproto.NewDecodeBuf(invLayer.Query)
		query := dBuf.Object()
		buf := cp.handleInvokeQuery(query, msgId)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLAuthSendCode:
		cp.HandleAuthSendCode(obj, msgId, salt, sessionId)
	case *mtproto.TLAuthSignIn:
		cp.HandleAuthSignIn(obj, msgId, salt, sessionId)
	case *mtproto.TLAuthSignUp:
		cp.HandleAuthSignUp(obj, msgId, salt, sessionId)
	case *mtproto.TLLangpackGetLanguages:
		// Standalone langpack request (not in invoke) - use gzip compression
		langData := buildLangpackResponse()
		compressed, err := gzipCompress(langData)
		buf := mtproto.NewEncodeBuf(len(compressed) + 64)
		buf.Int(-212046591); buf.Long(msgId)
		if err != nil {
			logf(1, "Failed to gzip compress langpack response: %v\n", err)
			buf.Bytes(langData)
		} else {
			buf.Int(0x3072cfa1) // gzip_packed
			buf.String(string(compressed)) // Use String() for proper TL encoding
		}
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLHelpGetNearestDc, *mtproto.TLHelpGetCountriesList:
		buf := cp.overlapWithInvokeRes(obj, msgId)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLMessagesGetStickers:
		cp.encodeAndSend(messages_stickers, msgId, salt, sessionId, 1024)
	case *mtproto.TLHelpGetPromoData:
		promoData := mtproto.MakeTLHelpPromoDataEmpty(&mtproto.Help_PromoData{
			Expires: int32(time.Now().Unix() + 3600),
		})
		cp.encodeAndSend(promoData, msgId, salt, sessionId, 512)
	case *mtproto.TLHelpGetTermsOfServiceUpdate:
		termsUpdate := mtproto.MakeTLHelpTermsOfServiceUpdateEmpty(&mtproto.Help_TermsOfServiceUpdate{
			Expires: int32(time.Now().Unix() + 3600),
		})
		cp.encodeAndSend(termsUpdate, msgId, salt, sessionId, 512)
	case *mtproto.TLMessagesGetAvailableReactions:
		cp.encodeAndSend(available_reactions, msgId, salt, sessionId, 30000)
	case *mtproto.TLMessagesGetAttachMenuBots:
		result := &mtproto.TLAttachMenuBots{
			Data2: &mtproto.AttachMenuBots{
				PredicateName: "attachMenuBots",
				Constructor:   1011024320,
				Bots:          []*mtproto.AttachMenuBot{},
				Users:         []*mtproto.User{}}}
		cp.encodeAndSend(result, msgId, salt, sessionId, 512)
	case *mtproto.TLUpdatesGetState:
		// Get current state for authenticated user
		pts, qts, seq, date := int32(1), int32(0), int32(0), int32(time.Now().Unix())
		if cp.userID != 0 {
			var err error
			pts, qts, seq, date, err = GetUserState(cp.userID)
			if err != nil {
				logf(1, "[Conn %d] Failed to get user state: %v\n", cp.connID, err)
			}
		}

		result := &mtproto.TLUpdatesState{
			Data2: &mtproto.Updates_State{
				PredicateName: "updates_state",
				Constructor:   -1519637954,
				Pts:           pts,
				Qts:           qts,
				Date:          date,
				Seq:           seq,
				UnreadCount:   0}}
		cp.encodeAndSend(result, msgId, salt, sessionId, 512)
	case *mtproto.TLUpdatesGetDifference:
		cp.HandleUpdatesGetDifference(obj, msgId, salt, sessionId)
	case *mtproto.TLMessagesGetPinnedDialogs:
		result := &mtproto.TLMessagesPeerDialogs{
			Data2: &mtproto.Messages_PeerDialogs{
				PredicateName: "messages_peerDialogs",
				Constructor:   863093588,
				Dialogs:       []*mtproto.Dialog{},
				Messages:      []*mtproto.Message{},
				Chats:         []*mtproto.Chat{},
				Users:         []*mtproto.User{},
				State: &mtproto.Updates_State{
					PredicateName: "updates_state",
					Constructor:   -1519637954,
					Pts:           1,
					Date:          int32(time.Now().Unix()),
					Seq:           -1}}}
		cp.encodeAndSend(result, msgId, salt, sessionId, 512)
	case *mtproto.TLHelpGetPremiumPromo:
		cp.encodeAndSend(help_premiumpromo, msgId, salt, sessionId, 1024)
	case *mtproto.TLAccountUpdateStatus:
		boolTrue := mtproto.MakeTLBoolTrue(nil)
		cp.encodeAndSend(boolTrue, msgId, salt, sessionId, 512)
	case *mtproto.TLContactsGetTopPeers:
		topPeers := mtproto.MakeTLContactsTopPeers(&mtproto.Contacts_TopPeers{
			Categories: []*mtproto.TopPeerCategoryPeers{},
			Chats:      []*mtproto.Chat{},
			Users:      []*mtproto.User{},
		})
		cp.encodeAndSend(topPeers, msgId, salt, sessionId, 512)
	case *mtproto.TLAccountGetNotifySettings:
		peerNotif := &mtproto.TLPeerNotifySettings{
			Data2: &mtproto.PeerNotifySettings{
				PredicateName: "peerNotifySettings",
				Constructor:   -1472527322,
				ShowPreviews: &mtproto.Bool{
					PredicateName: "boolTrue",
					Constructor:   -1720552011},
				Silent: &mtproto.Bool{
					PredicateName: "boolFalse",
					Constructor:   -1132882121},
				MuteUntil: &wrapperspb.Int32Value{}}}
		cp.encodeAndSend(peerNotif, msgId, salt, sessionId, 512)
	case *mtproto.TLAccountGetContactSignUpNotification:
		boolTrue := &mtproto.TLBoolTrue{
			Data2: &mtproto.Bool{
				PredicateName: "boolTrue",
				Constructor:   -1720552011}}
		cp.encodeAndSend(boolTrue, msgId, salt, sessionId, 512)
	case *mtproto.TLHelpGetInviteText:
		inviteTxt := &mtproto.TLHelpInviteText{
			Data2: &mtproto.Help_InviteText{}}
		cp.encodeAndSend(inviteTxt, msgId, salt, sessionId, 512)
	case *mtproto.TLMessagesGetDialogs:
		cp.HandleMessagesGetDialogs(obj, msgId, salt, sessionId)
	case *mtproto.TLMessagesGetFavedStickers:
		result := &mtproto.TLMessagesFavedStickers{
			Data2: &mtproto.Messages_FavedStickers{
				PredicateName: "messages_favedStickers",
				Constructor:   750063767,
				Packs:         []*mtproto.StickerPack{},
				Stickers:      []*mtproto.Document{}}}
		cp.encodeAndSend(result, msgId, salt, sessionId, 512)
	case *mtproto.TLMessagesGetEmojiStickers:
		result := &mtproto.TLMessagesAllStickers{
			Data2: &mtproto.Messages_AllStickers{
				PredicateName: "messages_allStickers",
				Constructor:   -843329861,
				Sets:          []*mtproto.StickerSet{}}}
		cp.encodeAndSend(result, msgId, salt, sessionId, 512)
	case *mtproto.TLMessagesGetEmojiKeywords, *mtproto.TLMessagesGetEmojiKeywordsDifference:
		result := &mtproto.TLEmojiKeywordsDifference{
			Data2: &mtproto.EmojiKeywordsDifference{
				PredicateName: "emojiKeywordsDifference",
				Constructor:   1556570557,
				LangCode:      "en-US",
				Keywords:      []*mtproto.EmojiKeyword{}}}
		cp.encodeAndSend(result, msgId, salt, sessionId, 512)
	case *mtproto.TLMessagesSetTyping:
		cp.HandleMessagesSetTyping(obj, msgId, salt, sessionId)
	case *mtproto.TLRpcDropAnswer:
		dropAnswer := &mtproto.TLRpcAnswerUnknown{
			Data2: &mtproto.RpcDropAnswer{
				PredicateName: "rpc_answer_unknown",
				Constructor:   1579864942}}
		cp.encodeAndSend(dropAnswer, msgId, salt, sessionId, 512)
	case *mtproto.TLContactsGetStatuses:
		ev := mtproto.NewEncodeBuf(512)
		ev.Int(-212046591); ev.Long(msgId)
		ev.Int(481674261); ev.Int(0)
		cp.send(ev.GetBuf(), salt, sessionId)
	case *mtproto.TLContactsGetContacts:
		cp.HandleContactsGetContactsDB(obj, msgId, salt, sessionId)
	case *mtproto.TLContactsImportContacts:
		cp.HandleContactsImportContacts(obj, msgId, salt, sessionId)
	case *mtproto.TLMessagesGetPeerDialogs:
		cp.HandleMessagesGetPeerDialogs(obj, msgId, salt, sessionId)
	case *mtproto.TLMessagesGetPeerSettings:
		cp.HandleMessagesGetPeerSettings(obj, msgId, salt, sessionId)
	case *mtproto.TLMessagesGetHistory:
		cp.HandleMessagesGetHistory(obj, msgId, salt, sessionId)
	case *mtproto.TLMessagesSendMessage:
		cp.HandleMessagesSendMessage(obj, msgId, salt, sessionId)
	case *mtproto.TLUsersGetFullUser:
		cp.HandleUsersGetFullUser(obj, msgId, salt, sessionId)
	case *mtproto.TLMessagesGetAllDrafts:
		cp.HandleMessagesGetAllDrafts(msgId, salt, sessionId)
	case *mtproto.TLMessagesGetScheduledHistory:
		cp.HandleMessagesGetScheduledHistory(obj, msgId, salt, sessionId)
	case *mtproto.TLMessagesSearch:
		cp.HandleMessagesSearch(obj, msgId, salt, sessionId)
	case *mtproto.TLMessagesReadHistory:
		result := &mtproto.TLMessagesAffectedMessages{
			Data2: &mtproto.Messages_AffectedMessages{
				PredicateName: "messages_affectedMessages",
				Constructor:   -2066640507,
				Pts:           3,
				PtsCount:      1,
			},
		}
		cp.encodeAndSend(result, msgId, salt, sessionId, 512)
	case *mtproto.TLMessagesGetMessagesReactions:
		cp.HandleMessagesGetMessagesReactions(obj, msgId, salt, sessionId)
	case *mtproto.TLMessagesGetArchivedStickers:
		result := &mtproto.TLMessagesArchivedStickers{
			Data2: &mtproto.Messages_ArchivedStickers{
				PredicateName: "messages_archivedStickers",
				Constructor:   1338747336,
				Sets:          []*mtproto.StickerSetCovered{},
			},
		}
		cp.encodeAndSend(result, msgId, salt, sessionId, 512)
	case *mtproto.TLMessagesGetSearchCounters:
		// Return empty vector of search counters
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result
		buf.Long(msgId)
		buf.Int(481674261) // vector constructor
		buf.Int(0) // count = 0 (empty vector)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLMessagesGetStickerSet:
		stickerSet := obj.GetStickerset()
		if stickerSet != nil {
			// Check PredicateName first
			switch stickerSet.PredicateName {
			case "inputStickerSetShortName":
				switch stickerSet.ShortName {
				case "tg_placeholders_android":
					cp.encodeAndSend(tg_placeholders_android, msgId, salt, sessionId, 30000)
					return
				case "EmojiAnimations":
					cp.encodeAndSend(emoji_animations, msgId, salt, sessionId, 30000)
					return
				}
			case "inputStickerSetDice":
				switch stickerSet.Emoticon {
				case "🎯":
					cp.encodeAndSend(animated_dart, msgId, salt, sessionId, 30000)
					return
				case "🎲":
					cp.encodeAndSend(animated_dice, msgId, salt, sessionId, 30000)
					return
				}
			case "inputStickerSetAnimatedEmoji":
				cp.encodeAndSend(animated_emojies, msgId, salt, sessionId, 30000)
				return
			case "inputStickerSetPremiumGifts":
				cp.encodeAndSend(gifts_premium, msgId, salt, sessionId, 30000)
				return
			case "inputStickerSetEmojiGenericAnimations":
				cp.encodeAndSend(generic_animations, msgId, salt, sessionId, 30000)
				return
			}
		}

		// If nothing matches, return a not found error or empty response
		logf(1, "Sticker set not found: %+v\n", stickerSet)
	case *mtproto.TLMessagesGetFeaturedStickers, *mtproto.TLMessagesGetFeaturedEmojiStickers:
		cp.encodeAndSend(featured_stickers, msgId, salt, sessionId, 30000)
	case *mtproto.TLMessagesGetDialogFiltersF19ED96D:
		result := &mtproto.Vector_DialogFilter{
			Datas: []*mtproto.DialogFilter{},
		}
		cp.encodeAndSend(result, msgId, salt, sessionId, 512)
	case *mtproto.TLUploadGetFile:
		location := obj.GetLocation()
		// Telegram protocol uses either INT64 or INT32 for offset depending on layer
		offset := obj.GetOffset_INT64()
		if offset == 0 {
			offset = int64(obj.GetOffset_INT32())
		}
		limit := obj.GetLimit()

		// Default limit if not specified (Telegram uses 512KB chunks for large files)
		if limit == 0 {
			limit = 1024 * 1024 // 1MB default
		}

		logf(2, "[Conn %d] upload.getFile: offset=%d, limit=%d\n", cp.connID, offset, limit)

		if location != nil && location.PredicateName == "inputDocumentFileLocation" {
			// Get full file data from database
			fileData, err := FindFileDataByID(location.Id)
			if err != nil || fileData == nil {
				logf(1, "[Conn %d] File data not found for document %d: %v\n", cp.connID, location.Id, err)
				// Return empty file instead of empty bytes
				result := &mtproto.TLUploadFile{
					Data2: &mtproto.Upload_File{
						PredicateName: "upload_file",
						Constructor:   157948117,
						Type: &mtproto.Storage_FileType{
							PredicateName: "storage_filePartial",
							Constructor:   1086091090,
						},
						Mtime: int32(time.Now().Unix()),
						Bytes: []byte{},
					},
				}
				buf := mtproto.NewEncodeBuf(512)
				buf.Int(-212046591)
				buf.Long(msgId)
				result.Encode(buf, 158)
				cp.send(buf.GetBuf(), salt, sessionId)
				return
			}

			// TGS files (and other Telegram files) are stored as raw bytes, NOT gzipped
			// The data should be sent as-is to the client
			// If your database has gzipped data, you need to decompress it first
			// For now, send the data as-is (client will handle decompression if needed)

			fileSize := int64(len(fileData))
			logf(1, "[Conn %d] upload.getFile doc=%d offset=%d limit=%d fileSize=%d\n",
				cp.connID, location.Id, offset, limit, fileSize)

			// Log first few bytes to debug
			if fileSize > 0 {
				preview := fileData
				if fileSize > 20 {
					preview = fileData[:20]
				}
				logf(2, "[Conn %d] File preview (hex): %x\n", cp.connID, preview)
			}

			// Extract the requested chunk
			var chunk []byte
			if offset < fileSize {
				endOffset := offset + int64(limit)
				if endOffset > fileSize {
					endOffset = fileSize
				}
				chunk = fileData[offset:endOffset]
			} else {
				// Offset beyond file size - return empty
				chunk = []byte{}
			}

			// Always use storage_filePartial for consistency
			// Telegram client handles this correctly for both complete and chunked files
			result := &mtproto.TLUploadFile{
				Data2: &mtproto.Upload_File{
					PredicateName: "upload_file",
					Constructor:   157948117,
					Type: &mtproto.Storage_FileType{
						PredicateName: "storage_filePartial",
						Constructor:   1086091090,
					},
					Mtime: int32(time.Now().Unix()),
					Bytes: chunk,
				},
			}

			logf(1, "[Conn %d] Sending file chunk: %d bytes (offset %d-%d of %d)\n",
				cp.connID, len(chunk), offset, offset+int64(len(chunk)), fileSize)

			buf := mtproto.NewEncodeBuf(len(chunk)+512)
			buf.Int(-212046591) // rpc_result constructor
			buf.Long(msgId)     // original request msg_id
			result.Encode(buf, 158)
			cp.send(buf.GetBuf(), salt, sessionId)
		}
	case *mtproto.TLMsgContainer:
		for _, m := range obj.Messages {
			logf(1, "In container %T\n", m.Object)
			cp.replyMsg(m.Object, m.MsgId, salt, sessionId)
		}
	default:
		logf(1, "Not found %T\n", obj)
	}
}