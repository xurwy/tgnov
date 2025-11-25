package main

import (
	"fmt"

	"github.com/teamgram/proto/mtproto"

	"google.golang.org/protobuf/types/known/wrapperspb"
)

// datafile len 185
// MsgId: 7574052661736315905
func main() {
	result := &mtproto.TLRpcResult{
    ReqMsgId: 7574052660154174464,
    Result:   &mtproto.TLContactsImportedContacts{
        Data2: &mtproto.Contacts_ImportedContacts{
            PredicateName: "contacts_importedContacts",
            Constructor:   2010127419,
            Imported:      []*mtproto.ImportedContact{
                &mtproto.ImportedContact{
                    PredicateName: "importedContact",
                    Constructor:   -1052885936,
                    UserId:        1271292179},
            },
            PopularInvites: []*mtproto.PopularContact{},
            RetryContacts:  []int64{},
            Users:          []*mtproto.User{
                &mtproto.User{
                    PredicateName: "user",
                    Constructor:   -1885878744,
                    Id:            1271292179,
                    Contact:       true,
                    MutualContact: true,
                    AccessHash:    &wrapperspb.Int64Value{
                        Value: 8958681173931933652},
                    FirstName: &wrapperspb.StringValue{
                        Value: "U"},
                    LastName: &wrapperspb.StringValue{
                        Value: "2"},
                    Status: &mtproto.UserStatus{
                        PredicateName: "userStatusOffline",
                        Constructor:   9203775,
                        WasOnline:     1763471112},
                    },
            }}}}

	fmt.Printf("Object loaded successfully: %T\n", result)
	fmt.Printf("Object content: %+v\n", result)
}
