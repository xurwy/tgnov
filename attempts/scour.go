package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/teamgram/proto/mtproto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// 1271292217
// 1271284286

func generateUserID() int64 {
	// 2^32 = 4,294,967,296
	// Range: 1B to 4,294,967,295
	// maxRange := int64(4294967296 - 1000000000) // 3,294,967,296
	// n, _ := rand.Int(rand.Reader, big.NewInt(maxRange))
	// return 2093050309
	return 1271284286
	// return n.Int64() + 1000000000
}

func main() {
/*
	result := &mtproto.Users_UserFull{
		PredicateName: "users_userFull",
		Constructor:   997004590,
		FullUser: &mtproto.UserFull{
			PredicateName:       "userFull",
			Constructor:         -120378643,
			PhoneCallsAvailable: true,
			CanPinMessage:       true,
			VideoCallsAvailable: true,
			Id:                  1271292179,
			Settings: &mtproto.PeerSettings{
				PredicateName: "peerSettings",
				Constructor:   -1525149427},
			NotifySettings: &mtproto.PeerNotifySettings{
				PredicateName: "peerNotifySettings",
				Constructor:   -1472527322},
			PremiumGifts: nil},
		Chats: []*mtproto.Chat{},
		Users: []*mtproto.User{
			{
				PredicateName: "user",
				Constructor:   -1885878744,
				Id:            1271292179,
				Contact:       true,
				MutualContact: true,
				AccessHash: &wrapperspb.Int64Value{
					Value: 8958681173931933652},
				FirstName: &wrapperspb.StringValue{
					Value: "U"},
				LastName: &wrapperspb.StringValue{
					Value: "2"},
				Status: &mtproto.UserStatus{
					PredicateName: "userStatusOffline",
					Constructor:   9203775,
					WasOnline:     1763471112},
				RestrictionReason: nil,
				Usernames:         nil},
		}}
	*/
	userObj := &mtproto.User{
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
			PredicateName: "userStatusOffline",
			Constructor:   9203775,
			WasOnline:     0},
		RestrictionReason: nil,
		Usernames:         nil,
	}


	// Use explicit constructor for compatibility
	fullUser := &mtproto.UserFull{
		PredicateName:       "userFull",
		Constructor:         mtproto.TLConstructor(-120378643), // Old userFull variant
		PhoneCallsAvailable: false,
		CanPinMessage:       true,
		VideoCallsAvailable: false,
		Id:                  1271292217,
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
	
	resbuf := mtproto.NewEncodeBuf(1024)
	result.Encode(resbuf, 158)

	resbuff := resbuf.GetBuf()

	// Patch offset 4: The encoding writes constructor -1813324973 (0x93eadb53) for layer 158,
	// but the target expects -120378643 (0xf8d32aed), an older UserFull variant.
	// This cannot be controlled via the Constructor field - the library overrides it based on layer.
	if len(resbuff) >= 8 {
		binary.LittleEndian.PutUint32(resbuff[4:8], 4174588653) // -120378643 as uint32
	}

	// Write resbuff to file
	os.WriteFile("/home/u/dev/telegram2/tgnov/attempts/resbuff.bin", resbuff, 0644)

	for i := 0; i < len(resbuff); i += 4 {
		if i+4 <= len(resbuff) {
			val := uint32(binary.LittleEndian.Uint32(resbuff[i : i+4]))
			fmt.Printf("Offset %15d: %15d\n", i, val)
			if val == 1271292179 {
				fmt.Println("found id 1")
			}
		}
	}
	// binData, _ := os.ReadFile("/home/u/dev/telegram/japp/mirror/CommData1/buff_1764237811620.bin")
	binData, _ := os.ReadFile("/home/u/dev/telegram/japp/mirror/CommData1/buff_1764237811620.bin")

	valrep := generateUserID()
	fmt.Println(valrep)
	buf := make([]byte, 4)
	ivalrep := uint32(valrep)
	fmt.Println(ivalrep)
	binary.LittleEndian.PutUint32(buf, ivalrep)
	copy(binData[12:16], buf)
	copy(binData[68:72], buf)
	// Read bytes as int32 values (4 bytes per int32)
	for i := 0; i < len(binData); i += 4 {
		if i+4 <= len(binData) {
			val := uint32(binary.LittleEndian.Uint32(binData[i : i+4]))
			fmt.Printf("Offset %15d: %15d %d\n", i, val, ivalrep)
			if val == ivalrep {
				fmt.Println("found id")
			}
		}
	}
}
