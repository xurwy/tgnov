package main

import (
	"github.com/teamgram/proto/mtproto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var help_premiumpromo = &mtproto.TLHelpPremiumPromo{
	Data2: &mtproto.Help_PremiumPromo{
		PredicateName: "help_premiumPromo",
		Constructor:   1395946908,
		StatusText:    "By subscribing to Teamgram Premium you agree to the Teamgram Terms of Service and Privacy Policy.\n\nRestore Purchases",
		StatusEntities: []*mtproto.MessageEntity{
			{
				PredicateName: "messageEntityTextUrl",
				Constructor:   1990644519,
				Offset:        61,
				Length:        16,
				Url:           "https://sendsmessenger.co/en/terms-of-service"},
			{
				PredicateName: "messageEntityTextUrl",
				Constructor:   1990644519,
				Offset:        82,
				Length:        14,
				Url:           "https://sendsmessenger.co/en/term-and-privacy-policy"},
			{
				PredicateName: "messageEntityTextUrl",
				Constructor:   1990644519,
				Offset:        99,
				Length:        17,
				Url:           "sends://restore_purchases"},
		},
		VideoSections: []string{"animated_emoji", "translations", "peer_colors", "infinite_reactions", "emoji_status", "faster_download", "app_icons", "premium_stickers", "animated_userpics", "effects", "saved_tags", "last_seen", "more_upload", "profile_badge"},
		Videos: []*mtproto.Document{
			{
				PredicateName: "documentEmpty",
				Constructor:   922273905,
				Id:            1904240454984011776,
				FileReference: nil,
				Thumbs:        nil,
				VideoThumbs:   nil,
				Attributes:    nil},
			{
				PredicateName: "documentEmpty",
				Constructor:   922273905,
				Id:            1904240462135300096,
				FileReference: nil,
				Thumbs:        nil,
				VideoThumbs:   nil,
				Attributes:    nil},
			{
				PredicateName: "documentEmpty",
				Constructor:   922273905,
				Id:            1904240459736158208,
				FileReference: nil,
				Thumbs:        nil,
				VideoThumbs:   nil,
				Attributes:    nil},
			{
				PredicateName: "documentEmpty",
				Constructor:   922273905,
				Id:            1904240456875642880,
				FileReference: nil,
				Thumbs:        nil,
				VideoThumbs:   nil,
				Attributes:    nil},
			{
				PredicateName: "documentEmpty",
				Constructor:   922273905,
				Id:            1904240456250691584,
				FileReference: nil,
				Thumbs:        nil,
				VideoThumbs:   nil,
				Attributes:    nil},
			{
				PredicateName: "documentEmpty",
				Constructor:   922273905,
				Id:            1904240454040293376,
				FileReference: nil,
				Thumbs:        nil,
				VideoThumbs:   nil,
				Attributes:    nil},
			{
				PredicateName: "documentEmpty",
				Constructor:   922273905,
				Id:            1904240464530247680,
				FileReference: nil,
				Thumbs:        nil,
				VideoThumbs:   nil,
				Attributes:    nil},
			{
				PredicateName: "documentEmpty",
				Constructor:   922273905,
				Id:            1904240460516298752,
				FileReference: nil,
				Thumbs:        nil,
				VideoThumbs:   nil,
				Attributes:    nil},
			{
				PredicateName: "documentEmpty",
				Constructor:   922273905,
				Id:            1904240455617351680,
				FileReference: nil,
				Thumbs:        nil,
				VideoThumbs:   nil,
				Attributes:    nil},
			{
				PredicateName: "documentEmpty",
				Constructor:   922273905,
				Id:            1904240459002155008,
				FileReference: nil,
				Thumbs:        nil,
				VideoThumbs:   nil,
				Attributes:    nil},
			{
				PredicateName: "documentEmpty",
				Constructor:   922273905,
				Id:            1904240462915440640,
				FileReference: nil,
				Thumbs:        nil,
				VideoThumbs:   nil,
				Attributes:    nil},
			{
				PredicateName: "documentEmpty",
				Constructor:   922273905,
				Id:            1904240458121351168,
				FileReference: nil,
				Thumbs:        nil,
				VideoThumbs:   nil,
				Attributes:    nil},
			{
				PredicateName: "documentEmpty",
				Constructor:   922273905,
				Id:            1904240463599112192,
				FileReference: nil,
				Thumbs:        nil,
				VideoThumbs:   nil,
				Attributes:    nil},
			{
				PredicateName: "documentEmpty",
				Constructor:   922273905,
				Id:            1904240461216747520,
				FileReference: nil,
				Thumbs:        nil,
				VideoThumbs:   nil,
				Attributes:    nil},
		},
		PeriodOptions: []*mtproto.PremiumSubscriptionOption{
			{
				PredicateName: "premiumSubscriptionOption",
				Constructor:   1596792306,
				Months:        1,
				Currency:      "CNY",
				Amount:        2899,
				BotUrl:        "https://t.me/PremiumBot?start=1",
				StoreProduct: &wrapperspb.StringValue{
					Value: "org.telegram.telegramPremium.monthly"}},
			{
				PredicateName: "premiumSubscriptionOption",
				Constructor:   1596792306,
				Months:        12,
				Currency:      "CNY",
				Amount:        20999,
				BotUrl:        "https://t.me/PremiumBot?start=12",
				StoreProduct: &wrapperspb.StringValue{
					Value: "org.telegram.telegramPremium.annual"}},
		},
		Users: []*mtproto.User{
			{
				PredicateName: "user",
				Constructor:   -1885878744,
				Id:            1271292217,
				Self:          true,
				Contact:       true,
				MutualContact: true,
				AccessHash: &wrapperspb.Int64Value{
					Value: 1249598286941389209},
				FirstName: &wrapperspb.StringValue{
					Value: "U"},
				LastName: &wrapperspb.StringValue{
					Value: "6"},
				Phone: &wrapperspb.StringValue{
					Value: "6281998219323"},
				Status: &mtproto.UserStatus{
					PredicateName: "userStatusOnline",
					Constructor:   -306628279,
					Expires:       1764237870},
				RestrictionReason: nil,
				Usernames:         nil},
		}}}
