package main

import (
	"time"

	"github.com/teamgram/proto/mtproto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// HandleUpdatesGetDifference handles TL_updates_getDifference requests
func (cp *ConnProp) HandleUpdatesGetDifference(obj *mtproto.TLUpdatesGetDifference, msgId, salt, sessionId int64) {
	logf(1, "[Conn %d] updates.getDifference for user %d\n", cp.connID, cp.userID)

	if cp.userID == 0 {
		logf(1, "[Conn %d] Not authenticated\n", cp.connID)
		return
	}

	// Update last seen when user checks for updates
	UpdateUserLastSeen(cp.userID)

	// Get client's current state
	clientPts := obj.GetPts()
	clientDate := obj.GetDate()
	clientQts := obj.GetQts()

	logf(1, "[Conn %d] Client state: pts=%d, date=%d, qts=%d\n", cp.connID, clientPts, clientDate, clientQts)

	// Get server's current state for this user
	serverPts, serverQts, serverSeq, serverDate, err := GetUserState(cp.userID)
	if err != nil {
		logf(1, "[Conn %d] Failed to get user state: %v\n", cp.connID, err)
		serverDate = int32(time.Now().Unix())
	}

	logf(1, "[Conn %d] Server state: pts=%d, qts=%d, seq=%d, date=%d\n", cp.connID, serverPts, serverQts, serverSeq, serverDate)

	// Get pending messages (messages sent to this user that they haven't received)
	pendingMessages, err := GetPendingMessages(cp.userID, clientPts)
	if err != nil {
		logf(1, "[Conn %d] Failed to get pending messages: %v\n", cp.connID, err)
		pendingMessages = []MessageDoc{}
	}

	logf(1, "[Conn %d] Found %d pending messages\n", cp.connID, len(pendingMessages))

	// If no updates, return differenceEmpty
	if len(pendingMessages) == 0 {
		result := &mtproto.TLUpdatesDifferenceEmpty{
			Data2: &mtproto.Updates_Difference{
				PredicateName: "updates_differenceEmpty",
				Constructor:   1567990072,
				Date:          serverDate,
				Seq:           serverSeq,
			},
		}
		cp.encodeAndSend(result, msgId, salt, sessionId, 512)
		return
	}

	// Build updates for new messages
	var updates []*mtproto.Update
	var messages []*mtproto.Message
	var users []*mtproto.User
	userMap := make(map[int64]bool)

	for _, msg := range pendingMessages {
		// For the RECIPIENT (cp.userID), this is an incoming message
		// Message.PeerId should point to the OTHER person in the dialog (the sender, msg.FromID)
		// Message.Out should be false (incoming)
		// Message.FromId should be the actual sender
		updates = append(updates, &mtproto.Update{
			PredicateName: "updateNewMessage",
			Constructor:   522914557,
			Message_MESSAGE: &mtproto.Message{
				PredicateName: "message",
				Constructor:   940666592,
				Id:            msg.ID,
				PeerId: &mtproto.Peer{
					PredicateName: "peerUser",
					Constructor:   1498486562,
					UserId:        msg.FromID, // Dialog peer = the sender (the OTHER person)
				},
				Out: false, // Incoming message for the recipient
				FromId: &mtproto.Peer{
					PredicateName: "peerUser",
					Constructor:   1498486562,
					UserId:        msg.FromID, // Actual sender
				},
				Date:    msg.Date,
				Message: msg.Message,
			},
			Pts_INT32: msg.Pts,
			PtsCount:  1,
		})

		// Also add to messages array
		messages = append(messages, &mtproto.Message{
			PredicateName: "message",
			Constructor:   940666592,
			Id:            msg.ID,
			PeerId: &mtproto.Peer{
				PredicateName: "peerUser",
				Constructor:   1498486562,
				UserId:        msg.FromID, // Dialog peer = the sender (the OTHER person)
			},
			Out: false,
			FromId: &mtproto.Peer{
				PredicateName: "peerUser",
				Constructor:   1498486562,
				UserId:        msg.FromID,
			},
			Date:    msg.Date,
			Message: msg.Message,
		})

		// Add sender to user map
		if !userMap[msg.FromID] {
			userMap[msg.FromID] = true
			sender, err := FindUserByID(msg.FromID)
			if err == nil && sender != nil {
				users = append(users, &mtproto.User{
					PredicateName: "user",
					Constructor:   -1885878744,
					Id:            sender.ID,
					Contact:       true,
					MutualContact: true,
					AccessHash: &wrapperspb.Int64Value{
						Value: sender.AccessHash,
					},
					FirstName: &wrapperspb.StringValue{
						Value: sender.FirstName,
					},
					LastName: &wrapperspb.StringValue{
						Value: sender.LastName,
					},
					Phone: &wrapperspb.StringValue{
						Value: sender.Phone,
					},
					Status: &mtproto.UserStatus{
						PredicateName: "userStatusOffline",
						Constructor:   9203775,
						WasOnline:     int32(sender.LastSeenAt.Unix()),
					},
				})
			}
		}
	}

	// Add self to users
	if !userMap[cp.userID] {
		selfUser, err := FindUserByID(cp.userID)
		if err == nil && selfUser != nil {
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
					PredicateName: "userStatusOnline",
					Constructor:   -306628279,
					Expires:       int32(time.Now().Unix() + 300),
				},
			})
		}
	}

	// Update user's pts to match the highest pts we're delivering
	if len(pendingMessages) > 0 {
		highestPts := pendingMessages[len(pendingMessages)-1].Pts
		err = UpdateUserPts(cp.userID, highestPts)
		if err != nil {
			logf(1, "[Conn %d] Failed to update user pts: %v\n", cp.connID, err)
		}
	}

	// Return updates.difference with the pending messages
	result := &mtproto.TLUpdatesDifference{
		Data2: &mtproto.Updates_Difference{
			PredicateName:  "updates_difference",
			Constructor:    16030880,
			NewMessages:    messages,
			NewEncryptedMessages: []*mtproto.EncryptedMessage{},
			OtherUpdates:   updates,
			Chats:          []*mtproto.Chat{},
			Users:          users,
			State: &mtproto.Updates_State{
				PredicateName: "updates_state",
				Constructor:   -1519637954,
				Pts:           serverPts,
				Qts:           serverQts,
				Date:          serverDate,
				Seq:           serverSeq,
				UnreadCount:   0,
			},
		},
	}

	cp.encodeAndSend(result, msgId, salt, sessionId, 8192)
}
