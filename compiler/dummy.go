package main

import (
	"fmt"
	"reflect"
	"time"

	"github.com/teamgram/proto/mtproto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

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




	case *mtproto.TLContactsImportContacts:
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
                    RestrictionReason: nil,
                    Usernames:         nil},
            }}}}

    buf := mtproto.NewEncodeBuf(512)
    result.Encode(buf, 158)
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
		
	default:
		fmt.Printf("Not found %T\n", obj)
	}
}