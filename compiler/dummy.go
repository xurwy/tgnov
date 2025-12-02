package main

import (
	"fmt"
	"reflect"
	"time"

	"github.com/teamgram/proto/mtproto"
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
	// first


	

	// last
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
