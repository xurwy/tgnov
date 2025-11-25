package main

import (
	"fmt"

	"github.com/teamgram/proto/mtproto"

	"google.golang.org/protobuf/types/known/wrapperspb"
)

func main() {
	result := &mtproto.TLRpcResult{
		ReqMsgId: 7574052660154174464,
		Result: &mtproto.TLContactsImportedContacts{
			Data2: &mtproto.Contacts_ImportedContacts{
				PredicateName: "contacts_importedContacts",
				Constructor:   2010127419,
				Imported: []*mtproto.ImportedContact{
					{
						PredicateName: "importedContact",
						Constructor:   -1052885936,
						UserId:        1271292179,
						ClientId:      0,
					},
				},
				PopularInvites: []*mtproto.PopularContact{},
				RetryContacts:  []int64{},
				Users: []*mtproto.User{
					{
						PredicateName:         "user",
						Constructor:           -1885878744,
						Id:                    1271292179,
						Self:                  false,
						Contact:               true,
						MutualContact:         true,
						Deleted:               false,
						Bot:                   false,
						BotChatHistory:        false,
						BotNochats:            false,
						Verified:              false,
						Restricted:            false,
						Min:                   false,
						BotInlineGeo:          false,
						Support:               false,
						Scam:                  false,
						ApplyMinPhoto:         false,
						Fake:                  false,
						BotAttachMenu:         false,
						Premium:               false,
						AttachMenuEnabled:     false,
						BotCanEdit:            false,
						CloseFriend:           false,
						StoriesHidden:         false,
						StoriesUnavailable:    false,
						ContactRequirePremium: false,
						BotBusiness:           false,
						BotHasMainApp:         false,
						AccessHash: &wrapperspb.Int64Value{
							Value: 8958681173931933652,
						},
						FirstName: &wrapperspb.StringValue{
							Value: "U",
						},
						LastName: &wrapperspb.StringValue{
							Value: "2",
						},
						Username: nil,
						Phone:    nil,
						Photo:    nil,
						Status: &mtproto.UserStatus{
							PredicateName: "userStatusOffline",
							Constructor:   9203775,
							Expires:       0,
							WasOnline:     1763471112,
							ByMe:          false,
						},
						BotInfoVersion:        nil,
						RestrictionReason:     nil,
						BotInlinePlaceholder:  nil,
						LangCode:              nil,
						EmojiStatus:           nil,
						Usernames:             nil,
						StoriesMaxId:          nil,
						Color_FLAGPEERCOLOR:   nil,
						ProfileColor:          nil,
						BotActiveUsers:        nil,
						BotVerificationIcon:   nil,
						SendPaidMessagesStars: nil,
						Color_FLAGINT32:       nil,
						BackgroundEmojiId:     nil,
						Color:                 nil,
					},
				},
			},
		},
	}

	fmt.Printf("%# v\n",result)
}