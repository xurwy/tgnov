package main

import (
	"fmt"

	"github.com/teamgram/proto/mtproto"
)



func main(){
    a := mtproto.TLContactsImportContacts{Constructor: 1234}
    fmt.Println(a)
}

