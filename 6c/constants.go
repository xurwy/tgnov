package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
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

func (cp *ConnProp) sendTLObjectResponse(obj mtproto.TLObject) { cp.conn.Write(cp.encode(obj)) }

var (
	cryptoCodec *AesCTR128Crypto
	AuthKey     []byte
	authKeyId   int64
	crAuthKey    *crypto.AuthKey
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
	cp.sendTLObjectResponse(serverDHParams)
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
	AuthKey = make([]byte, 256)
	copy(AuthKey[256-len(authKeyNum.Bytes()):], authKeyNum.Bytes())
	authKeyAuxHash := make([]byte, len(newNonce))
	copy(authKeyAuxHash, newNonce)
	authKeyAuxHash = append(authKeyAuxHash, byte(0x01))
	sha1D := sha1.Sum(AuthKey)
	authKeyAuxHash = append(authKeyAuxHash, sha1D[:]...)
	sha1E := sha1.Sum(authKeyAuxHash[:len(authKeyAuxHash)-12])
	authKeyAuxHash = append(authKeyAuxHash, sha1E[:]...)
	authKeyId = int64(binary.LittleEndian.Uint64(authKeyAuxHash[len(newNonce)+1+12 : len(newNonce)+1+12+8]))
	
	os.WriteFile("auth_key.bin", AuthKey, 0644); 
	
	dhGen := mtproto.MakeTLDhGenOk(&mtproto.SetClient_DHParamsAnswer{Nonce: nonce, ServerNonce: serverNonce, NewNonceHash1: calcNewNonceHash(newNonce, AuthKey, 0x01)}).To_SetClient_DHParamsAnswer()
	cp.sendTLObjectResponse(dhGen)
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

func (cp *ConnProp) handleQuery(query mtproto.TLObject, msgId int64) *mtproto.EncodeBuf {
	buf := mtproto.NewEncodeBuf(512); buf.Int(-212046591); buf.Long(msgId)
	
	switch query.(type) {
	case *mtproto.TLLangpackGetLanguages: buf.Int(481674261); buf.Int(0)
	case *mtproto.TLHelpGetNearestDc: buf.Int(-1910892683); buf.String("CN"); buf.Int(1); buf.Int(1)
	case *mtproto.TLHelpGetCountriesList: buf.Int(-2016381538); buf.Int(481674261); buf.Int(0); buf.Int(0)
	default: buf.Int(481674261); buf.Int(0)
	}
	
	return buf
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
		buf := cp.handleQuery(query, msgId)
		cp.send(buf.GetBuf(), salt, sessionId)
		
	case *mtproto.TLAuthSendCode:
		fmt.Printf("%d TLAuthSendCode Phone: %s\n", msgId, o.(*mtproto.TLAuthSendCode).PhoneNumber)
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591); buf.Long(msgId); buf.Int(0x5e002502); buf.Int(17)
		buf.Int(-1073693790); buf.Int(5); buf.String("21e22a8d47e7fc8241239f6a0102786c"); buf.Int(60)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLAuthSignIn:
		fmt.Printf("%d TLAuthSignIn Phone: %s, Code: %s\n", msgId, o.(*mtproto.TLAuthSignIn).PhoneNumber, o.(*mtproto.TLAuthSignIn).PhoneCode_FLAGSTRING.Value)
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591); buf.Long(msgId); buf.Int(1148485274); buf.Int(0)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLAuthSignUp:
		authSignUp := o.(*mtproto.TLAuthSignUp)
		fmt.Printf("%d TLAuthSignUp Phone: %s, Name: %s %s\n", msgId, authSignUp.PhoneNumber, authSignUp.FirstName, authSignUp.LastName)
		
		user := mtproto.MakeTLUser(&mtproto.User{
			Id:            777009,
			Self:          true,
			Contact:       true,
			MutualContact: true,
			AccessHash:    &wrapperspb.Int64Value{Value: 7748176802034418738},
			FirstName:     &wrapperspb.StringValue{Value: authSignUp.FirstName},
			LastName:      &wrapperspb.StringValue{Value: authSignUp.LastName},
			Phone:         &wrapperspb.StringValue{Value: authSignUp.PhoneNumber},
			Status: &mtproto.UserStatus{
				PredicateName: "userStatusOnline",
				Constructor:   -306628279,
				Expires:       1763554375,
			},
		}).To_User()
		
		authAuth := mtproto.MakeTLAuthAuthorization(&mtproto.Auth_Authorization{
			SetupPasswordRequired: false,
			OtherwiseReloginDays:  nil,
			TmpSessions:           nil,
			FutureAuthToken:       nil,
			User:                  user,
		})
		
		buf := mtproto.NewEncodeBuf(512)
		
		buf.Int(-212046591) // rpc_result constructor  
		buf.Long(msgId)     // ReqMsgId
		authAuth.Encode(buf, 158)
		
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLHelpGetPromoData:
		promoData := mtproto.MakeTLHelpPromoDataEmpty(&mtproto.Help_PromoData{
			Expires: int32(time.Now().Unix() + 3600),
		})
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		promoData.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLMsgContainer:
		fmt.Println("Going inside TLMsgContainer")
		for _, m := range obj.Messages { 
			// Process each message in the container asynchronously
			go cp.replyMsg(m.Object, m.MsgId, salt, sessionId) 
		}
	case *mtproto.TLUsersGetFullUser:
		fmt.Println("========== FROM *mtproto.TLUsersGetFullUser ========")
		// response := createUserFullResponse(msgId)
		// cp.send(response, salt, sessionId)
	case *mtproto.TLAccountUpdateStatus:
		boolTrue := mtproto.MakeTLBoolTrue(nil)
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		boolTrue.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLLangpackGetLanguages, *mtproto.TLHelpGetNearestDc, *mtproto.TLHelpGetCountriesList:
		buf := cp.handleQuery(o, msgId)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLHelpGetTermsOfServiceUpdate:
		termsUpdate := mtproto.MakeTLHelpTermsOfServiceUpdateEmpty(&mtproto.Help_TermsOfServiceUpdate{
			Expires: int32(time.Now().Unix() + 3600),
		})
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		termsUpdate.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLAccountGetNotifySettings:
		notifySettings := mtproto.MakeTLPeerNotifySettings(&mtproto.PeerNotifySettings{
			ShowPreviews: mtproto.MakeTLBoolTrue(nil).To_Bool(),
			Silent:       mtproto.MakeTLBoolFalse(nil).To_Bool(),
			MuteUntil:    &wrapperspb.Int32Value{Value: 0},
		})
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		notifySettings.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLAccountGetContactSignUpNotification:
		boolFalse := mtproto.MakeTLBoolTrue(nil)
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		boolFalse.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLMessagesGetStickers:
		stickers := mtproto.MakeTLMessagesStickers(&mtproto.Messages_Stickers{
			Hash:     0,
			Stickers: []*mtproto.Document{},
		})
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		stickers.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLMessagesGetStickerSet:
		stickerSetNotModified := mtproto.MakeTLMessagesStickerSetNotModified(nil)
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		stickerSetNotModified.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLMessagesGetPinnedDialogs, *mtproto.TLMessagesGetPeerDialogs:
		peerDialogs := mtproto.MakeTLMessagesPeerDialogs(&mtproto.Messages_PeerDialogs{
			Dialogs:  []*mtproto.Dialog{},
			Messages: []*mtproto.Message{},
			Chats:    []*mtproto.Chat{},
			Users:    []*mtproto.User{},
			State: mtproto.MakeTLUpdatesState(&mtproto.Updates_State{
				Pts:         1,
				Qts:         0,
				Date:        int32(time.Now().Unix()),
				Seq:         -1,
				UnreadCount: 0,
			}).To_Updates_State(),
		})
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		peerDialogs.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLMessagesGetDialogs:
		dialogs := mtproto.MakeTLMessagesDialogsSlice(&mtproto.Messages_Dialogs{
			Dialogs:  []*mtproto.Dialog{},
			Messages: []*mtproto.Message{},
			Chats:    []*mtproto.Chat{},
			Users:    []*mtproto.User{},
			Count:    0,
		})
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		dialogs.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)

	case *mtproto.TLHelpGetPremiumPromo, *mtproto.TLMessagesGetAttachMenuBots, *mtproto.TLMessagesGetDialogFiltersF19ED96D, *mtproto.TLHelpGetInviteText:
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591); buf.Long(msgId); buf.Int(558156313); buf.Int(400); buf.String("ERR_ENTERPRISE_IS_BLOCKED")
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLMessagesGetAvailableReactions:
		availableReactionsNotModified := mtproto.MakeTLMessagesAvailableReactionsNotModified(nil)
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		availableReactionsNotModified.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLUpdatesGetState:
		updatesState := mtproto.MakeTLUpdatesState(&mtproto.Updates_State{
			Pts:         1,
			Qts:         0,
			Date:        int32(time.Now().Unix()),
			Seq:         -1,
			UnreadCount: 0,
		})
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		updatesState.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLContactsGetContacts:
		contacts := mtproto.MakeTLContactsContacts(&mtproto.Contacts_Contacts{
			Contacts:   []*mtproto.Contact{},
			SavedCount: 0,
			Users:      []*mtproto.User{},
		})
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		contacts.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLMessagesGetFavedStickers:
		favedStickers := mtproto.MakeTLMessagesFavedStickers(&mtproto.Messages_FavedStickers{
			Hash:     0,
			Packs:    []*mtproto.StickerPack{},
			Stickers: []*mtproto.Document{},
		})
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		favedStickers.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLMessagesGetFeaturedStickers, *mtproto.TLMessagesGetFeaturedEmojiStickers:
		featuredStickers := mtproto.MakeTLMessagesFeaturedStickers(&mtproto.Messages_FeaturedStickers{
			Hash:     0,
			Count:    0,
			Sets:     []*mtproto.StickerSetCovered{},
			Unread:   []int64{},
		})
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		featuredStickers.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLContactsGetTopPeers:
		
		topPeers := mtproto.MakeTLContactsTopPeers(&mtproto.Contacts_TopPeers{
			Categories: []*mtproto.TopPeerCategoryPeers{},
			Chats:      []*mtproto.Chat{},
			Users:      []*mtproto.User{},
		})
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor  
		buf.Long(msgId)   
		topPeers.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLContactsGetStatuses:
		contactsStatuses := &mtproto.Vector_ContactStatus{
			Datas: []*mtproto.ContactStatus{},
		}
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		contactsStatuses.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLMessagesGetAllDrafts:
		user := mtproto.MakeTLUser(&mtproto.User{
			Id:            777008,
			Self:          true,
			Contact:       true,
			MutualContact: true,
			AccessHash:    &wrapperspb.Int64Value{Value: 8646839358227092202},
			FirstName:     &wrapperspb.StringValue{Value: "U"},
			LastName:      &wrapperspb.StringValue{Value: "T"},
			Phone:         &wrapperspb.StringValue{Value: "6281698219323"},
			Status: &mtproto.UserStatus{
				PredicateName: "userStatusOnline",
				Constructor:   -306628279,
				Expires:       int32(time.Now().Unix() + 60),
			},
		}).To_User()
		
		updates := mtproto.MakeTLUpdates(&mtproto.Updates{
			Updates: []*mtproto.Update{},
			Users:   []*mtproto.User{user},
			Chats:   []*mtproto.Chat{},
			Date:    int32(time.Now().Unix()),
			Seq:     0,
		})
		
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		updates.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLContactsImportContacts:
		importedContacts := mtproto.MakeTLContactsImportedContacts(&mtproto.Contacts_ImportedContacts{
			Imported:       []*mtproto.ImportedContact{},
			PopularInvites: []*mtproto.PopularContact{},
			RetryContacts:  []int64{},
			Users:          []*mtproto.User{},
		})
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		importedContacts.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId)
	case *mtproto.TLRpcDropAnswer:
		// Client is dropping/cancelling a previous RPC call
		// Just acknowledge it with RpcAnswerDropped 
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		buf.Int(-1539647305) // rpc_answer_dropped constructor
		buf.Long(msgId) // msg_id
		buf.Int(0) // seq_no
		buf.Int(0) // bytes
		cp.send(buf.GetBuf(), salt, sessionId)
	default:
		fmt.Printf("Not found %T\n", obj)
	}
}

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
	_ = line
	_ = shortName
	_ = filename
	_ = msg
	if level <= DEBUG_LVL {
		timestamp := time.Now().Format("15:04:05.000")
		log.Printf("%s %4d %8s:%3d %20s() | %s", timestamp, level, filename, line, shortName, msg)
	}
}
