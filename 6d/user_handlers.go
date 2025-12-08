package main

import (
	"encoding/binary"
	"time"

	"github.com/teamgram/proto/mtproto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// HandleContactsGetContacts handles TL_contacts_getContacts requests
func (cp *ConnProp) HandleContactsGetContacts(obj *mtproto.TLContactsGetContacts, msgId, salt, sessionId int64) {
	logf(1, "[Conn %d] contacts.getContacts for user %d\n", cp.connID, cp.userID)

	result := &mtproto.TLContactsContacts{
		Data2: &mtproto.Contacts_Contacts{
			PredicateName: "contacts_contacts",
			Constructor:   -1219778094,
			Contacts:      []*mtproto.Contact{},
			SavedCount:    0,
			Users:         []*mtproto.User{},
		},
	}

	cp.encodeAndSend(result, msgId, salt, sessionId, 512)
}

// HandleMessagesGetPeerDialogs handles TL_messages_getPeerDialogs requests
func (cp *ConnProp) HandleMessagesGetPeerDialogs(obj *mtproto.TLMessagesGetPeerDialogs, msgId, salt, sessionId int64) {
	logf(1, "[Conn %d] messages.getPeerDialogs\n", cp.connID)

	peers := obj.GetPeers()
	var dialogs []*mtproto.Dialog
	var users []*mtproto.User

	for _, inputDialogPeer := range peers {
		inputPeer := inputDialogPeer.GetPeer()
		if inputPeer == nil {
			continue
		}

		requestedUserId := inputPeer.UserId
		logf(1, "[Conn %d] Requested user_id: %d\n", cp.connID, requestedUserId)

		// Look up the requested user
		user, err := FindUserByID(requestedUserId)
		if err != nil || user == nil {
			logf(1, "[Conn %d] Failed to find user %d: %v\n", cp.connID, requestedUserId, err)
			continue
		}

		// Determine if this is self
		isSelf := (requestedUserId == cp.userID)

		// Create dialog
		dialog := &mtproto.Dialog{
			PredicateName: "dialog",
			Constructor:   -1460809483,
			Peer: &mtproto.Peer{
				PredicateName: "peerUser",
				Constructor:   1498486562,
				UserId:        user.ID,
			},
			TopMessage:           0,
			ReadInboxMaxId:       0,
			ReadOutboxMaxId:      0,
			UnreadCount:          0,
			UnreadMentionsCount:  0,
			UnreadReactionsCount: 0,
			NotifySettings: &mtproto.PeerNotifySettings{
				PredicateName: "peerNotifySettings",
				Constructor:   -1472527322,
			},
		}
		dialogs = append(dialogs, dialog)

		// Add user to users array
		users = append(users, &mtproto.User{
			PredicateName: "user",
			Constructor:   -1885878744,
			Id:            user.ID,
			Self:          isSelf,
			Contact:       isSelf,
			MutualContact: isSelf,
			AccessHash: &wrapperspb.Int64Value{
				Value: user.AccessHash,
			},
			FirstName: &wrapperspb.StringValue{
				Value: user.FirstName,
			},
			LastName: &wrapperspb.StringValue{
				Value: user.LastName,
			},
			Phone: &wrapperspb.StringValue{
				Value: user.Phone,
			},
			Status: &mtproto.UserStatus{
				PredicateName: "userStatusOnline",
				Constructor:   -306628279,
				Expires:       int32(time.Now().Unix() + 60),
			},
		})
	}

	result := &mtproto.TLMessagesPeerDialogs{
		Data2: &mtproto.Messages_PeerDialogs{
			PredicateName: "messages_peerDialogs",
			Constructor:   863093588,
			Dialogs:       dialogs,
			Messages:      []*mtproto.Message{},
			Chats:         []*mtproto.Chat{},
			Users:         users,
			State: &mtproto.Updates_State{
				PredicateName: "updates_state",
				Constructor:   -1519637954,
				Pts:           1,
				Date:          int32(time.Now().Unix()),
				Seq:           -1,
			},
		},
	}

	cp.encodeAndSend(result, msgId, salt, sessionId, 2048)
}

// HandleUsersGetFullUser handles TL_users_getFullUser requests
func (cp *ConnProp) HandleUsersGetFullUser(obj *mtproto.TLUsersGetFullUser, msgId, salt, sessionId int64) {
	logf(1, "[Conn %d] users.getFullUser\n", cp.connID)

	inputUser := obj.GetId()
	if inputUser == nil {
		logf(1, "[Conn %d] No user ID in request\n", cp.connID)
		return
	}

	// Determine which user to look up based on predicate
	var requestedUserId int64
	var isSelf bool

	switch inputUser.PredicateName {
	case "inputUserSelf":
		requestedUserId = cp.userID
		isSelf = true
	case "inputUser":
		requestedUserId = inputUser.UserId
		// Special case: user_id=0 means "self" in some contexts
		if requestedUserId == 0 {
			requestedUserId = cp.userID
			isSelf = true
		} else {
			isSelf = (requestedUserId == cp.userID)
		}
	default:
		logf(1, "[Conn %d] Unknown inputUser predicate: %s\n", cp.connID, inputUser.PredicateName)
		return
	}

	logf(1, "[Conn %d] Requested user_id: %d (self: %v)\n", cp.connID, requestedUserId, isSelf)

	// Get user from database
	user, err := FindUserByID(requestedUserId)
	if err != nil || user == nil {
		logf(1, "[Conn %d] Failed to find user %d: %v\n", cp.connID, requestedUserId, err)
		return
	}

	userObj := &mtproto.User{
		PredicateName: "user",
		Constructor:   -1885878744,
		Id:            user.ID,
		Self:          isSelf,
		Contact:       true,
		MutualContact: true,
		AccessHash: &wrapperspb.Int64Value{
			Value: user.AccessHash},
		FirstName: &wrapperspb.StringValue{
			Value: user.FirstName},
		LastName: &wrapperspb.StringValue{
			Value: user.LastName},
		Phone: &wrapperspb.StringValue{
			Value: user.Phone},
		Status: &mtproto.UserStatus{
			PredicateName: "userStatusOffline",
			Constructor:   9203775,
			WasOnline:     0},
		RestrictionReason: nil,
		Usernames:         nil,
	}

	fullUser := &mtproto.UserFull{
		PredicateName:       "userFull",
		Constructor:         mtproto.TLConstructor(-120378643), // Old userFull variant
		PhoneCallsAvailable: false,
		CanPinMessage:       true,
		VideoCallsAvailable: false,
		Id:                  user.ID,
		Settings: &mtproto.PeerSettings{
			PredicateName: "peerSettings",
			Constructor:   -1525149427},
		NotifySettings: &mtproto.PeerNotifySettings{
			PredicateName: "peerNotifySettings",
			Constructor:   -1472527322},
		PremiumGifts: nil}

	result := &mtproto.Users_UserFull{
		PredicateName: "users_userFull",
		Constructor:   997004590,
		FullUser:      fullUser,
		Chats:         []*mtproto.Chat{},
		Users:         []*mtproto.User{userObj}}

	// Encode the result with layer 158
	resbuf := mtproto.NewEncodeBuf(1024)
	result.Encode(resbuf, 158)

	resbuff := resbuf.GetBuf()

	// Patch offset 4 to use old UserFull constructor
	// The encoding writes constructor -1813324973 (0x93eadb53) for layer 158,
	// but the Android client expects -120378643 (0xf8d32aed), an older UserFull variant.
	// This cannot be controlled via the Constructor field - the library overrides it based on layer.
	if len(resbuff) >= 8 {
		binary.LittleEndian.PutUint32(resbuff[4:8], 4174588653) // -120378643 as uint32
	}

	// Send the patched response
	buf := mtproto.NewEncodeBuf(12 + len(resbuff))
	buf.Int(-212046591) // rpc_result
	buf.Long(msgId)
	buf.Bytes(resbuff)
	cp.send(buf.GetBuf(), salt, sessionId)
}

// HandleMessagesGetAllDrafts handles TL_messages_getAllDrafts requests
func (cp *ConnProp) HandleMessagesGetAllDrafts(msgId, salt, sessionId int64) {
	logf(1, "[Conn %d] messages.getAllDrafts for user %d\n", cp.connID, cp.userID)

	if cp.userID == 0 {
		logf(1, "[Conn %d] Not authenticated, returning empty drafts\n", cp.connID)
		result := &mtproto.TLUpdates{
			Data2: &mtproto.Updates{
				PredicateName: "updates",
				Constructor:   1957577280,
				Updates:       []*mtproto.Update{},
				Users:         []*mtproto.User{},
				Chats:         []*mtproto.Chat{},
				Date:          int32(time.Now().Unix()),
				Seq:           0,
			},
		}
		cp.encodeAndSend(result, msgId, salt, sessionId, 512)
		return
	}

	user, err := FindUserByID(cp.userID)
	if err != nil || user == nil {
		logf(1, "[Conn %d] Failed to find user %d: %v\n", cp.connID, cp.userID, err)
		result := &mtproto.TLUpdates{
			Data2: &mtproto.Updates{
				PredicateName: "updates",
				Constructor:   1957577280,
				Updates:       []*mtproto.Update{},
				Users:         []*mtproto.User{},
				Chats:         []*mtproto.Chat{},
				Date:          int32(time.Now().Unix()),
				Seq:           0,
			},
		}
		cp.encodeAndSend(result, msgId, salt, sessionId, 512)
		return
	}

	result := &mtproto.TLUpdates{
		Data2: &mtproto.Updates{
			PredicateName: "updates",
			Constructor:   1957577280,
			Updates:       []*mtproto.Update{},
			Users: []*mtproto.User{
				{
					PredicateName: "user",
					Constructor:   -1885878744,
					Id:            user.ID,
					Self:          true,
					Contact:       true,
					MutualContact: true,
					AccessHash: &wrapperspb.Int64Value{
						Value: user.AccessHash,
					},
					FirstName: &wrapperspb.StringValue{
						Value: user.FirstName,
					},
					LastName: &wrapperspb.StringValue{
						Value: user.LastName,
					},
					Phone: &wrapperspb.StringValue{
						Value: user.Phone,
					},
					Status: &mtproto.UserStatus{
						PredicateName: "userStatusOnline",
						Constructor:   -306628279,
						Expires:       int32(time.Now().Unix() + 60),
					},
				},
			},
			Chats: []*mtproto.Chat{},
			Date:  int32(time.Now().Unix()),
			Seq:   0,
		},
	}

	cp.encodeAndSend(result, msgId, salt, sessionId, 1024)
}
