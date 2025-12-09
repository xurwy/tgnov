package main

import (
	"github.com/teamgram/proto/mtproto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (cp *ConnProp) HandleMessagesGetDialogs(obj *mtproto.TLMessagesGetDialogs, msgId, salt, sessionId int64) {
	logf(1, "[Conn %d] ========== messages.getDialogs for user %d ==========\n", cp.connID, cp.userID)

	if cp.userID == 0 {
		logf(1, "[Conn %d] Not authenticated\n", cp.connID)
		return
	}

	// Get limit from request, default to 100
	limit := obj.GetLimit()
	if limit == 0 {
		limit = 100
	}

	// Get dialogs from database
	dialogs, err := GetDialogs(cp.userID, limit)
	if err != nil {
		logf(1, "[Conn %d] Failed to get dialogs: %v\n", cp.connID, err)
		dialogs = []DialogDoc{}
	}

	logf(1, "[Conn %d] Found %d dialogs\n", cp.connID, len(dialogs))

	var mtprotoDialogs []*mtproto.Dialog
	var messages []*mtproto.Message
	var users []*mtproto.User
	userMap := make(map[int64]*UserDoc)

	// First, collect all users we need
	for _, dialog := range dialogs {
		if _, exists := userMap[dialog.PeerUserID]; !exists {
			peerUser, err := FindUserByID(dialog.PeerUserID)
			if err == nil && peerUser != nil {
				userMap[dialog.PeerUserID] = peerUser
			}
		}
	}

	// Add self
	if _, exists := userMap[cp.userID]; !exists {
		selfUser, err := FindUserByID(cp.userID)
		if err == nil && selfUser != nil {
			userMap[cp.userID] = selfUser
		}
	}

	// Build dialogs
	for _, dialog := range dialogs {
		logf(1, "[Conn %d] Dialog: user=%d, peer=%d, top_msg=%d, unread=%d, cp.userID=%d\n",
			cp.connID, dialog.UserID, dialog.PeerUserID, dialog.TopMessage, dialog.UnreadCount, cp.userID)

		if dialog.UserID != cp.userID {
			logf(1, "[Conn %d] ERROR: Dialog user_id %d != current user %d, skipping\n",
				cp.connID, dialog.UserID, cp.userID)
			continue
		}

		if dialog.PeerUserID == cp.userID {
			logf(1, "[Conn %d] ERROR: Dialog peer_user_id %d == current user %d (self-dialog), skipping\n",
				cp.connID, dialog.PeerUserID, cp.userID)
			continue
		}

		// Create dialog object
		mtprotoDialogs = append(mtprotoDialogs, &mtproto.Dialog{
			PredicateName: "dialog",
			Constructor:   -1460809483,
			Peer: &mtproto.Peer{
				PredicateName: "peerUser",
				Constructor:   1498486562,
				UserId:        dialog.PeerUserID,
			},
			TopMessage:           dialog.TopMessage,
			ReadInboxMaxId:       dialog.ReadInboxMaxID,
			ReadOutboxMaxId:      dialog.ReadOutboxMaxID,
			UnreadCount:          dialog.UnreadCount,
			UnreadMentionsCount:  0,
			UnreadReactionsCount: 0,
			NotifySettings: &mtproto.PeerNotifySettings{
				PredicateName: "peerNotifySettings",
				Constructor:   -1472527322,
			},
		})

		// Get the top message for this dialog
		if dialog.TopMessage > 0 {
			msg, err := GetMessageByID(dialog.DialogID, dialog.TopMessage)
			if err != nil {
				logf(1, "[Conn %d] Failed to get message %d: %v\n", cp.connID, dialog.TopMessage, err)
				continue
			}
			if msg == nil {
				logf(1, "[Conn %d] Message %d not found\n", cp.connID, dialog.TopMessage)
				continue
			}

			isOut := (msg.FromID == cp.userID)

			logf(1, "[Conn %d] Top message %d: from=%d, peer=%d, isOut=%v\n",
				cp.connID, msg.ID, msg.FromID, msg.PeerID, isOut)

			messages = append(messages, &mtproto.Message{
				PredicateName: "message",
				Constructor:   940666592,
				Id:            msg.ID,
				PeerId: &mtproto.Peer{
					PredicateName: "peerUser",
					Constructor:   1498486562,
					UserId:        dialog.PeerUserID,
				},
				Out: isOut,
				FromId: &mtproto.Peer{
					PredicateName: "peerUser",
					Constructor:   1498486562,
					UserId:        msg.FromID,
				},
				Date:    msg.Date,
				Message: msg.Message,
			})
		}
	}

	if selfUser, exists := userMap[cp.userID]; exists {
		users = append(users, &mtproto.User{
			PredicateName: "user",
			Constructor:   -1885878744,
			Id:            selfUser.ID,
			Self:          true,
			Contact:       true,
			MutualContact: true,
			AccessHash: &wrapperspb.Int64Value{
				Value: selfUser.AccessHash,
			},
			FirstName: &wrapperspb.StringValue{
				Value: selfUser.FirstName,
			},
			LastName: &wrapperspb.StringValue{
				Value: selfUser.LastName,
			},
			Phone: &wrapperspb.StringValue{
				Value: selfUser.Phone,
			},
			Status: &mtproto.UserStatus{
				PredicateName: "userStatusOffline",
				Constructor:   9203775,
				WasOnline:     int32(selfUser.LastSeenAt.Unix()),
			},
		})
		logf(1, "[Conn %d] User %d: self=true, name=%s\n", cp.connID, selfUser.ID, selfUser.FirstName)
	}

	for userID, userDoc := range userMap {
		if userID == cp.userID {
			continue
		}

		users = append(users, &mtproto.User{
			PredicateName: "user",
			Constructor:   -1885878744,
			Id:            userDoc.ID,
			Self:          false,
			Contact:       true,
			MutualContact: true,
			AccessHash: &wrapperspb.Int64Value{
				Value: userDoc.AccessHash,
			},
			FirstName: &wrapperspb.StringValue{
				Value: userDoc.FirstName,
			},
			LastName: &wrapperspb.StringValue{
				Value: userDoc.LastName,
			},
			Phone: &wrapperspb.StringValue{
				Value: userDoc.Phone,
			},
			Status: &mtproto.UserStatus{
				PredicateName: "userStatusOffline",
				Constructor:   9203775,
				WasOnline:     int32(userDoc.LastSeenAt.Unix()),
			},
		})

		logf(1, "[Conn %d] User %d: self=false, name=%s\n", cp.connID, userID, userDoc.FirstName)
	}

	result := &mtproto.TLMessagesDialogsSlice{
		Data2: &mtproto.Messages_Dialogs{
			PredicateName: "messages_dialogsSlice",
			Constructor:   1910543603,
			Count:         int32(len(mtprotoDialogs)),
			Dialogs:       mtprotoDialogs,
			Messages:      messages,
			Chats:         []*mtproto.Chat{},
			Users:         users,
		},
	}

	logf(1, "[Conn %d] Returning %d dialogs, %d messages, %d users\n",
		cp.connID, len(mtprotoDialogs), len(messages), len(users))

	for i, user := range users {
		logf(1, "[Conn %d] User[%d]: id=%d, self=%v, first_name=%s\n",
			cp.connID, i, user.Id, user.Self, user.FirstName.Value)
	}

	cp.encodeAndSend(result, msgId, salt, sessionId, 8192)
	logf(1, "[Conn %d] ========== END messages.getDialogs ==========\n", cp.connID)
}
