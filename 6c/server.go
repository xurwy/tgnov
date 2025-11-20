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
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var ctr int
type ConnProp struct { 
	conn net.Conn
	cryp *AesCTR128Crypto
	ctrInitialized bool
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
		buffer := make([]byte, 5000)
		if n, err := conn.Read(buffer); n == 0 { break } else {
			fmt.Printf("(%d) %02x\n", n, buffer[:10])
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
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
	case *mtproto.TLDestroySession:
		destroyData := mtproto.NewEncodeBuf(8); destroyData.Long(obj.SessionId)
		buf := mtproto.NewEncodeBuf(32)
		buf.Int(-212046591); buf.Long(msgId); buf.Int(-501201412); buf.Bytes(destroyData.GetBuf())
		cp.send(buf.GetBuf(), salt, sessionId, msgId)
	case *mtproto.TLInvokeWithLayer:
		invLayer := o.(*mtproto.TLInvokeWithLayer)
		newSessionData := mtproto.NewEncodeBuf(512)
		newSessionData.Int(-1631450872); newSessionData.Long(msgId); newSessionData.Long(time.Now().UnixNano()); newSessionData.Long(salt)
		cp.send(newSessionData.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
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
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
		
	case *mtproto.TLAuthSendCode:
		fmt.Printf("%d TLAuthSendCode Phone: %s\n", msgId, o.(*mtproto.TLAuthSendCode).PhoneNumber)
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591); buf.Long(msgId); buf.Int(0x5e002502); buf.Int(17)
		buf.Int(-1073693790); buf.Int(5); buf.String("21e22a8d47e7fc8241239f6a0102786c"); buf.Int(60)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLAuthSignIn:
		fmt.Printf("%d TLAuthSignIn Phone: %s, Code: %s\n", msgId, o.(*mtproto.TLAuthSignIn).PhoneNumber, o.(*mtproto.TLAuthSignIn).PhoneCode_FLAGSTRING.Value)
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591); buf.Long(msgId); buf.Int(1148485274); buf.Int(0)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
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
		
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())

	case *mtproto.TLHelpGetPromoData:
		promoData := mtproto.MakeTLHelpPromoDataEmpty(&mtproto.Help_PromoData{
			Expires: int32(time.Now().Unix() + 3600),
		})
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		promoData.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLMsgContainer:
		fmt.Println("Going inside TLMsgContainer")
		for _, m := range obj.Messages { cp.replyMsg(m.Object, m.MsgId, salt, sessionId) }
	case *mtproto.TLAccountUpdateStatus:
		boolTrue := mtproto.MakeTLBoolTrue(nil)
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		boolTrue.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLLangpackGetLanguages, *mtproto.TLHelpGetNearestDc, *mtproto.TLHelpGetCountriesList:
		buf := cp.handleQuery(o, msgId)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLHelpGetTermsOfServiceUpdate:
		termsUpdate := mtproto.MakeTLHelpTermsOfServiceUpdateEmpty(&mtproto.Help_TermsOfServiceUpdate{
			Expires: int32(time.Now().Unix() + 3600),
		})
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		termsUpdate.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
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
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLAccountGetContactSignUpNotification:
		boolFalse := mtproto.MakeTLBoolTrue(nil)
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		boolFalse.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLMessagesGetStickers:
		stickers := mtproto.MakeTLMessagesStickers(&mtproto.Messages_Stickers{
			Hash:     0,
			Stickers: []*mtproto.Document{},
		})
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		stickers.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLMessagesGetStickerSet:
		stickerSetNotModified := mtproto.MakeTLMessagesStickerSetNotModified(nil)
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		stickerSetNotModified.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLMessagesGetPinnedDialogs:
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
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLMessagesGetPeerDialogs, *mtproto.TLMessagesGetDialogs:
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
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLHelpGetPremiumPromo, *mtproto.TLMessagesGetAttachMenuBots, *mtproto.TLMessagesGetDialogFiltersF19ED96D, *mtproto.TLHelpGetInviteText:
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591); buf.Long(msgId); buf.Int(558156313); buf.Int(400); buf.String("ERR_ENTERPRISE_IS_BLOCKED")
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLMessagesGetAvailableReactions:
		availableReactionsNotModified := mtproto.MakeTLMessagesAvailableReactionsNotModified(nil)
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		availableReactionsNotModified.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
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
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
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
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLUsersGetFullUser:
		user := mtproto.MakeTLUser(&mtproto.User{
			Id:            777001,
			Self:          true,
			Contact:       true,
			MutualContact: true,
			AccessHash:    &wrapperspb.Int64Value{Value: 6279878546724348992},
			FirstName:     &wrapperspb.StringValue{Value: "alhamdulilah"},
			LastName:      &wrapperspb.StringValue{Value: "ya allah"},
			Phone:         &wrapperspb.StringValue{Value: "6281298219323"},
			Status: &mtproto.UserStatus{
				PredicateName: "userStatusOffline",
				Constructor:   9203775,
				WasOnline:     0,
			},
		}).To_User()
		
		userFull := mtproto.MakeTLUserFull(&mtproto.UserFull{
			CanPinMessage: true,
			Id:            777001,
			Settings: mtproto.MakeTLPeerSettings(&mtproto.PeerSettings{}).To_PeerSettings(),
			NotifySettings: mtproto.MakeTLPeerNotifySettings(&mtproto.PeerNotifySettings{}).To_PeerNotifySettings(),
			CommonChatsCount: 0,
		}).To_UserFull()
		
		usersUserFull := mtproto.MakeTLUsersUserFull(&mtproto.Users_UserFull{
			FullUser: userFull,
			Chats:    []*mtproto.Chat{},
			Users:    []*mtproto.User{user},
		})
		
		buf := mtproto.NewEncodeBuf(1024)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		usersUserFull.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
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
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
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
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
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
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
	case *mtproto.TLContactsGetStatuses:
		contactsStatuses := &mtproto.Vector_ContactStatus{
			Datas: []*mtproto.ContactStatus{},
		}
		buf := mtproto.NewEncodeBuf(512)
		buf.Int(-212046591) // rpc_result constructor
		buf.Long(msgId)
		contactsStatuses.Encode(buf, 158)
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
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
		cp.send(buf.GetBuf(), salt, sessionId, mtproto.GenerateMessageId())
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
	for i := 0; i < 50; i++ { if conn, err := listener.Accept(); err == nil { handleConnection(conn) } }
}