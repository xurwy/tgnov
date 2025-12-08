package main

import (
	"time"

	"github.com/teamgram/proto/mtproto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// HandleContactsImportContacts handles TL_contacts_importContacts requests
func (cp *ConnProp) HandleContactsImportContacts(obj *mtproto.TLContactsImportContacts, msgId, salt, sessionId int64) {
	logf(1, "[Conn %d] contacts.importContacts for user %d\n", cp.connID, cp.userID)

	if cp.userID == 0 {
		logf(1, "[Conn %d] Not authenticated\n", cp.connID)
		return
	}

	contacts := obj.GetContacts()
	var importedContacts []*mtproto.ImportedContact
	var importedUsers []*mtproto.User
	var retryContacts []int64

	for _, inputContact := range contacts {
		phone := inputContact.GetPhone()
		clientID := inputContact.GetClientId()

		// Normalize phone number - remove leading + if present
		normalizedPhone := phone
		if len(phone) > 0 && phone[0] == '+' {
			normalizedPhone = phone[1:]
		}

		// Look up user by phone number
		contactUser, err := FindUserByPhone(normalizedPhone)
		if err != nil || contactUser == nil {
			logf(1, "[Conn %d] User not found for phone %s, adding to retry\n", cp.connID, phone)
			retryContacts = append(retryContacts, clientID)
			continue
		}

		// Add contact relationship
		err = AddContact(cp.userID, contactUser.ID, phone, clientID)
		if err != nil {
			logf(1, "[Conn %d] Failed to add contact: %v\n", cp.connID, err)
			retryContacts = append(retryContacts, clientID)
			continue
		}

		// Build imported contact
		importedContacts = append(importedContacts, &mtproto.ImportedContact{
			PredicateName: "importedContact",
			Constructor:   -1052885936,
			UserId:        contactUser.ID,
			ClientId:      clientID,
		})

		// Build user object
		importedUsers = append(importedUsers, &mtproto.User{
			PredicateName: "user",
			Constructor:   -1885878744,
			Id:            contactUser.ID,
			Contact:       true,
			AccessHash: &wrapperspb.Int64Value{
				Value: contactUser.AccessHash},
			FirstName: &wrapperspb.StringValue{
				Value: contactUser.FirstName},
			LastName: &wrapperspb.StringValue{
				Value: contactUser.LastName},
			Status: &mtproto.UserStatus{
				PredicateName: "userStatusOffline",
				Constructor:   9203775,
				WasOnline:     int32(contactUser.LastSeenAt.Unix())},
		})
	}

	// Build and send response
	result := &mtproto.TLContactsImportedContacts{
		Data2: &mtproto.Contacts_ImportedContacts{
			PredicateName:  "contacts_importedContacts",
			Constructor:    2010127419,
			Imported:       importedContacts,
			PopularInvites: []*mtproto.PopularContact{},
			RetryContacts:  retryContacts,
			Users:          importedUsers,
		},
	}

	cp.encodeAndSend(result, msgId, salt, sessionId, 2048)

	// Note: We don't send additional updatePeerSettings for each contact
	// The imported contacts are already included in the main response above
	// Sending extra updates without proper pts management can cause client issues
}

// HandleContactsGetContacts handles TL_contacts_getContacts requests
func (cp *ConnProp) HandleContactsGetContactsDB(obj *mtproto.TLContactsGetContacts, msgId, salt, sessionId int64) {
	logf(1, "[Conn %d] contacts.getContacts for user %d\n", cp.connID, cp.userID)

	if cp.userID == 0 {
		logf(1, "[Conn %d] Not authenticated\n", cp.connID)
		return
	}

	// Get contacts from database
	contacts, err := GetContacts(cp.userID)
	if err != nil {
		logf(1, "[Conn %d] Failed to get contacts: %v\n", cp.connID, err)
		contacts = []ContactDoc{}
	}

	var contactsList []*mtproto.Contact
	var usersList []*mtproto.User

	for _, contact := range contacts {
		// Get contact user info
		contactUser, err := FindUserByID(contact.ContactUserID)
		if err != nil || contactUser == nil {
			continue
		}

		// Add to contacts list
		var mutualBool *mtproto.Bool
		if contact.Mutual {
			mutualBool = &mtproto.Bool{
				PredicateName: "boolTrue",
				Constructor:   -1720552011,
			}
		} else {
			mutualBool = &mtproto.Bool{
				PredicateName: "boolFalse",
				Constructor:   -1132882121,
			}
		}
		contactsList = append(contactsList, &mtproto.Contact{
			PredicateName: "contact",
			Constructor:   -2023500831,
			UserId:        contactUser.ID,
			Mutual:        mutualBool,
		})

		// Add to users list
		usersList = append(usersList, &mtproto.User{
			PredicateName: "user",
			Constructor:   -1885878744,
			Id:            contactUser.ID,
			Contact:       true,
			MutualContact: contact.Mutual,
			AccessHash: &wrapperspb.Int64Value{
				Value: contactUser.AccessHash},
			FirstName: &wrapperspb.StringValue{
				Value: contactUser.FirstName},
			LastName: &wrapperspb.StringValue{
				Value: contactUser.LastName},
			Status: &mtproto.UserStatus{
				PredicateName: "userStatusOffline",
				Constructor:   9203775,
				WasOnline:     int32(contactUser.LastSeenAt.Unix())},
		})
	}

	result := &mtproto.TLContactsContacts{
		Data2: &mtproto.Contacts_Contacts{
			PredicateName: "contacts_contacts",
			Constructor:   -1219778094,
			Contacts:      contactsList,
			SavedCount:    int32(len(contactsList)),
			Users:         usersList,
		},
	}

	cp.encodeAndSend(result, msgId, salt, sessionId, 4096)
}

// HandleMessagesGetPeerSettings handles TL_messages_getPeerSettings requests
func (cp *ConnProp) HandleMessagesGetPeerSettings(obj *mtproto.TLMessagesGetPeerSettings, msgId, salt, sessionId int64) {
	logf(1, "[Conn %d] messages.getPeerSettings\n", cp.connID)

	result := &mtproto.TLMessagesPeerSettings{
		Data2: &mtproto.Messages_PeerSettings{
			PredicateName: "messages_peerSettings",
			Constructor:   1753266509,
			Settings: &mtproto.PeerSettings{
				PredicateName: "peerSettings",
				Constructor:   -1525149427},
			Chats: []*mtproto.Chat{},
			Users: []*mtproto.User{},
		},
	}

	cp.encodeAndSend(result, msgId, salt, sessionId, 512)
}

// HandleMessagesGetHistory handles TL_messages_getHistory requests
func (cp *ConnProp) HandleMessagesGetHistory(obj *mtproto.TLMessagesGetHistory, msgId, salt, sessionId int64) {
	logf(1, "[Conn %d] messages.getHistory for user %d\n", cp.connID, cp.userID)

	if cp.userID == 0 {
		logf(1, "[Conn %d] Not authenticated\n", cp.connID)
		return
	}

	peer := obj.GetPeer()
	if peer == nil {
		logf(1, "[Conn %d] No peer in request\n", cp.connID)
		return
	}

	var peerUserID int64
	switch peer.PredicateName {
	case "inputPeerUser":
		peerUserID = peer.UserId
	case "inputPeerSelf":
		peerUserID = cp.userID
	default:
		logf(1, "[Conn %d] Unknown peer type: %s\n", cp.connID, peer.PredicateName)
		return
	}

	// Get dialog ID
	dialogID := GetDialogID(cp.userID, peerUserID)

	// Get messages from database
	limit := obj.GetLimit()
	if limit == 0 {
		limit = 50
	}
	messages, err := GetMessages(dialogID, limit)
	if err != nil {
		logf(1, "[Conn %d] Failed to get messages: %v\n", cp.connID, err)
		messages = []MessageDoc{}
	}

	// Convert to mtproto messages
	var mtprotoMessages []*mtproto.Message
	for _, msg := range messages {
		mtprotoMessages = append(mtprotoMessages, &mtproto.Message{
			PredicateName: "message",
			Constructor:   940666592,
			Id:            msg.ID,
			PeerId: &mtproto.Peer{
				PredicateName: "peerUser",
				Constructor:   1498486562,
				UserId:        msg.PeerID},
			Out: msg.Out,
			FromId: &mtproto.Peer{
				PredicateName: "peerUser",
				Constructor:   1498486562,
				UserId:        msg.FromID},
			Date:    msg.Date,
			Message: msg.Message,
		})
	}

	// Get users involved in the conversation
	var users []*mtproto.User
	userMap := make(map[int64]bool)

	// Add current user (self)
	if !userMap[cp.userID] {
		user, _ := FindUserByID(cp.userID)
		if user != nil {
			userMap[cp.userID] = true
			users = append(users, &mtproto.User{
				PredicateName: "user",
				Constructor:   -1885878744,
				Id:            user.ID,
				Self:          true,
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
					PredicateName: "userStatusOnline",
					Constructor:   -306628279,
					Expires:       int32(time.Now().Unix() + 300)},
			})
		}
	}

	// Add peer user if different from self
	if peerUserID != cp.userID && !userMap[peerUserID] {
		peerUser, _ := FindUserByID(peerUserID)
		if peerUser != nil {
			userMap[peerUserID] = true
			users = append(users, &mtproto.User{
				PredicateName: "user",
				Constructor:   -1885878744,
				Id:            peerUser.ID,
				Contact:       true,
				MutualContact: true,
				AccessHash: &wrapperspb.Int64Value{
					Value: peerUser.AccessHash},
				FirstName: &wrapperspb.StringValue{
					Value: peerUser.FirstName},
				LastName: &wrapperspb.StringValue{
					Value: peerUser.LastName},
				Phone: &wrapperspb.StringValue{
					Value: peerUser.Phone},
				Status: &mtproto.UserStatus{
					PredicateName: "userStatusOffline",
					Constructor:   9203775,
					WasOnline:     int32(peerUser.LastSeenAt.Unix())},
			})
		}
	}

	result := &mtproto.TLMessagesMessages{
		Data2: &mtproto.Messages_Messages{
			PredicateName: "messages_messages",
			Constructor:   -1938715001,
			Messages:      mtprotoMessages,
			Chats:         []*mtproto.Chat{},
			Users:         users,
		},
	}

	cp.encodeAndSend(result, msgId, salt, sessionId, 4096)
}

// HandleMessagesSendMessage handles TL_messages_sendMessage requests
func (cp *ConnProp) HandleMessagesSendMessage(obj *mtproto.TLMessagesSendMessage, msgId, salt, sessionId int64) {
	logf(1, "[Conn %d] messages.sendMessage for user %d\n", cp.connID, cp.userID)

	if cp.userID == 0 {
		logf(1, "[Conn %d] Not authenticated\n", cp.connID)
		return
	}

	peer := obj.GetPeer()
	message := obj.GetMessage()
	randomID := obj.GetRandomId()

	if peer == nil {
		logf(1, "[Conn %d] No peer in request\n", cp.connID)
		return
	}

	var peerUserID int64
	switch peer.PredicateName {
	case "inputPeerUser":
		peerUserID = peer.UserId
	default:
		logf(1, "[Conn %d] Unknown peer type: %s\n", cp.connID, peer.PredicateName)
		return
	}

	// Get dialog ID (same for both users in the conversation)
	dialogID := GetDialogID(cp.userID, peerUserID)

	// Get next message ID - this is atomic and global for the dialog
	// Both users will see the same message IDs
	messageID, err := GetNextMessageID(dialogID)
	if err != nil {
		logf(1, "[Conn %d] Failed to get next message ID: %v\n", cp.connID, err)
		return
	}

	logf(1, "[Conn %d] Sending message ID %d in dialog %s\n", cp.connID, messageID, dialogID)

	// Atomically increment user's pts counter
	// For a simple message send, we only have ONE pts-affecting update: the message itself
	// updateMessageID does NOT consume pts (it's just a mapping)
	// updateNewMessage consumes 1 pts
	ptsCount := int32(1)

	newPts, err := IncrementUserPts(cp.userID, ptsCount)
	if err != nil {
		logf(1, "[Conn %d] Failed to increment pts: %v\n", cp.connID, err)
		return
	}

	// Save message to database
	now := int32(time.Now().Unix())
	msgDoc := &MessageDoc{
		ID:       messageID,
		DialogID: dialogID,
		FromID:   cp.userID,
		PeerID:   peerUserID,
		Date:     now,
		Message:  message,
		Out:      true,
		RandomID: randomID,
		Pts:      newPts,
		CreatedAt: time.Now(),
	}

	err = SaveMessage(msgDoc)
	if err != nil {
		logf(1, "[Conn %d] Failed to save message: %v\n", cp.connID, err)
	}

	// Update dialog for sender (outgoing message)
	err = UpdateDialog(cp.userID, peerUserID, messageID, now, true)
	if err != nil {
		logf(1, "[Conn %d] Failed to update sender dialog: %v\n", cp.connID, err)
	}

	// Update dialog for recipient (incoming message)
	err = UpdateDialog(peerUserID, cp.userID, messageID, now, false)
	if err != nil {
		logf(1, "[Conn %d] Failed to update recipient dialog: %v\n", cp.connID, err)
	}

	// Get current user info
	user, _ := FindUserByID(cp.userID)
	var users []*mtproto.User
	if user != nil {
		users = append(users, &mtproto.User{
			PredicateName: "user",
			Constructor:   -1885878744,
			Id:            user.ID,
			Self:          true,
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
				PredicateName: "userStatusOnline",
				Constructor:   -306628279,
				Expires:       int32(time.Now().Unix() + 300)},
		})
	}

	// Build response with updates
	result := &mtproto.TLUpdates{
		Data2: &mtproto.Updates{
			PredicateName: "updates",
			Constructor:   1957577280,
			Updates: []*mtproto.Update{
				{
					PredicateName: "updateMessageID",
					Constructor:   1318109142,
					Id_INT32:      messageID,
					RandomId:      randomID,
				},
				{
					PredicateName: "updateNewMessage",
					Constructor:   522914557,
					Message_MESSAGE: &mtproto.Message{
						PredicateName: "message",
						Constructor:   940666592,
						Id:            messageID,
						PeerId: &mtproto.Peer{
							PredicateName: "peerUser",
							Constructor:   1498486562,
							UserId:        peerUserID},
						Out: true,
						FromId: &mtproto.Peer{
							PredicateName: "peerUser",
							Constructor:   1498486562,
							UserId:        cp.userID},
						Date:    now,
						Message: message,
					},
					Pts_INT32: newPts,    // The NEW pts after increment
					PtsCount:  ptsCount,  // How many pts units this update consumed
				},
			},
			Users: users,
			Chats: []*mtproto.Chat{},
			Date:  now,
			Seq:   0,
		},
	}

	cp.encodeAndSend(result, msgId, salt, sessionId, 4096)
}
// HandleMessagesGetScheduledHistory handles TL_messages_getScheduledHistory requests
func (cp *ConnProp) HandleMessagesGetScheduledHistory(obj *mtproto.TLMessagesGetScheduledHistory, msgId, salt, sessionId int64) {
	logf(1, "[Conn %d] messages.getScheduledHistory for user %d\n", cp.connID, cp.userID)

	if cp.userID == 0 {
		logf(1, "[Conn %d] Not authenticated\n", cp.connID)
		return
	}

	peer := obj.GetPeer()
	if peer == nil {
		logf(1, "[Conn %d] No peer in request\n", cp.connID)
		return
	}

	// Get the user ID from the peer
	var peerUserID int64
	switch peer.PredicateName {
	case "inputPeerUser":
		peerUserID = peer.UserId
	case "inputPeerSelf":
		peerUserID = cp.userID
	default:
		logf(1, "[Conn %d] Unknown peer type: %s\n", cp.connID, peer.PredicateName)
		return
	}

	// Get user info for the requested peer
	user, _ := FindUserByID(peerUserID)
	var users []*mtproto.User
	if user != nil {
		users = append(users, &mtproto.User{
			PredicateName: "user",
			Constructor:   -1885878744,
			Id:            user.ID,
			Contact:       true,
			AccessHash: &wrapperspb.Int64Value{
				Value: user.AccessHash},
			FirstName: &wrapperspb.StringValue{
				Value: user.FirstName},
			LastName: &wrapperspb.StringValue{
				Value: user.LastName},
			Status: &mtproto.UserStatus{
				PredicateName: "userStatusOffline",
				Constructor:   9203775,
				WasOnline:     int32(user.LastSeenAt.Unix())},
			RestrictionReason: nil,
			Usernames:         nil,
		})
	}

	// Return empty scheduled messages with the requested user info
	result := &mtproto.TLMessagesMessages{
		Data2: &mtproto.Messages_Messages{
			PredicateName: "messages_messages",
			Constructor:   -1938715001,
			Messages:      []*mtproto.Message{},
			Chats:         []*mtproto.Chat{},
			Users:         users,
		},
	}

	cp.encodeAndSend(result, msgId, salt, sessionId, 2048)
}

// HandleMessagesSearch handles TL_messages_search requests
func (cp *ConnProp) HandleMessagesSearch(obj *mtproto.TLMessagesSearch, msgId, salt, sessionId int64) {
	logf(1, "[Conn %d] messages.search for user %d\n", cp.connID, cp.userID)

	if cp.userID == 0 {
		logf(1, "[Conn %d] Not authenticated\n", cp.connID)
		return
	}

	peer := obj.GetPeer()
	if peer == nil {
		logf(1, "[Conn %d] No peer in request\n", cp.connID)
		return
	}

	// Get the user ID from the peer
	var peerUserID int64
	switch peer.PredicateName {
	case "inputPeerUser":
		peerUserID = peer.UserId
	case "inputPeerSelf":
		peerUserID = cp.userID
	default:
		logf(1, "[Conn %d] Unknown peer type: %s\n", cp.connID, peer.PredicateName)
		return
	}

	// Get user info for the requested peer
	user, _ := FindUserByID(peerUserID)
	var users []*mtproto.User
	if user != nil {
		users = append(users, &mtproto.User{
			PredicateName: "user",
			Constructor:   -1885878744,
			Id:            user.ID,
			Contact:       true,
			AccessHash: &wrapperspb.Int64Value{
				Value: user.AccessHash},
			FirstName: &wrapperspb.StringValue{
				Value: user.FirstName},
			LastName: &wrapperspb.StringValue{
				Value: user.LastName},
			Status: &mtproto.UserStatus{
				PredicateName: "userStatusOffline",
				Constructor:   9203775,
				WasOnline:     int32(user.LastSeenAt.Unix())},
			RestrictionReason: nil,
			Usernames:         nil,
		})
	}

	// Return empty search results (could be enhanced to actually search messages)
	result := &mtproto.TLMessagesMessages{
		Data2: &mtproto.Messages_Messages{
			PredicateName: "messages_messages",
			Constructor:   -1938715001,
			Messages:      []*mtproto.Message{},
			Chats:         []*mtproto.Chat{},
			Users:         users,
		},
	}

	cp.encodeAndSend(result, msgId, salt, sessionId, 2048)
}

// HandleMessagesSetTyping handles TL_messages_setTyping requests
func (cp *ConnProp) HandleMessagesSetTyping(obj *mtproto.TLMessagesSetTyping, msgId, salt, sessionId int64) {
	logf(2, "[Conn %d] messages.setTyping for user %d\n", cp.connID, cp.userID)

	if cp.userID == 0 {
		logf(1, "[Conn %d] Not authenticated\n", cp.connID)
		return
	}

	// Extract peer information
	peer := obj.GetPeer()
	action := obj.GetAction()

	if peer == nil {
		logf(1, "[Conn %d] No peer in setTyping request\n", cp.connID)
		return
	}

	// Get peer user ID
	var peerUserID int64
	switch peer.PredicateName {
	case "inputPeerUser":
		peerUserID = peer.UserId
	case "inputPeerSelf":
		peerUserID = cp.userID
	default:
		logf(2, "[Conn %d] Unsupported peer type for typing: %s\n", cp.connID, peer.PredicateName)
		// Still return true even for unsupported peers
	}

	// Log typing action
	if action != nil {
		logf(2, "[Conn %d] User %d typing to %d, action: %s\n",
			cp.connID, cp.userID, peerUserID, action.PredicateName)
	}

	// In a real production server, you would:
	// 1. Find all active connections for peerUserID
	// 2. Send them an updateUserTyping notification
	// For example:
	// update := &mtproto.TLUpdateUserTyping{
	//     Data2: &mtproto.Update{
	//         PredicateName: "updateUserTyping",
	//         Constructor:   -1071741569,
	//         UserId:        cp.userID,
	//         Action:        action,
	//     },
	// }
	// broadcastToPeerConnections(peerUserID, update, salt, sessionId)

	// Acknowledge to the sender
	boolTrue := &mtproto.TLBoolTrue{
		Data2: &mtproto.Bool{
			PredicateName: "boolTrue",
			Constructor:   -1720552011}}
	cp.encodeAndSend(boolTrue, msgId, salt, sessionId, 512)
}

// HandleMessagesGetMessagesReactions handles TL_messages_getMessagesReactions requests
func (cp *ConnProp) HandleMessagesGetMessagesReactions(obj *mtproto.TLMessagesGetMessagesReactions, msgId, salt, sessionId int64) {
	logf(1, "[Conn %d] messages.getMessagesReactions for user %d\n", cp.connID, cp.userID)

	if cp.userID == 0 {
		logf(1, "[Conn %d] Not authenticated\n", cp.connID)
		return
	}

	// Extract peer user ID from request
	peer := obj.GetPeer()
	var peerUserID int64

	switch peer.PredicateName {
	case "inputPeerUser":
		peerUserID = peer.UserId
	case "inputPeerSelf":
		peerUserID = cp.userID
	default:
		logf(1, "[Conn %d] Unsupported peer type: %s\n", cp.connID, peer.PredicateName)
		return
	}

	// Look up the peer user
	var users []*mtproto.User
	if peerUserID != 0 {
		peerUser, err := FindUserByID(peerUserID)
		if err == nil && peerUser != nil {
			users = append(users, &mtproto.User{
				PredicateName: "user",
				Constructor:   -1885878744,
				Id:            peerUser.ID,
				Self:          peerUser.Self,
				Contact:       peerUser.Contact,
				MutualContact: peerUser.MutualContact,
				AccessHash: &wrapperspb.Int64Value{
					Value: peerUser.AccessHash,
				},
				FirstName: &wrapperspb.StringValue{
					Value: peerUser.FirstName,
				},
				LastName: &wrapperspb.StringValue{
					Value: peerUser.LastName,
				},
				Phone: &wrapperspb.StringValue{
					Value: peerUser.Phone,
				},
				Status: &mtproto.UserStatus{
					PredicateName: "userStatusOffline",
					Constructor:   9203775,
					WasOnline:     int32(peerUser.LastSeenAt.Unix()),
				},
				RestrictionReason: nil,
				Usernames:         nil,
			})
		}
	}

	// Return TL_updates with empty updates array
	result := &mtproto.TLUpdates{
		Data2: &mtproto.Updates{
			PredicateName: "updates",
			Constructor:   1957577280,
			Updates:       []*mtproto.Update{},
			Users:         users,
			Chats:         []*mtproto.Chat{},
			Date:          int32(time.Now().Unix()),
			Seq:           0,
		},
	}

	cp.encodeAndSend(result, msgId, salt, sessionId, 2048)
}
