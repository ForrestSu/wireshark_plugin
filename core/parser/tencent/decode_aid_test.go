package tencent

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ForrestSu/wireshark_plugin/core/parser/tencent/stub/ad_packet"
)

func TestAidCodec(t *testing.T) {
	data := `{"aid":"4021","oaid":"4021","duration":325,"tpid":106,"isvip":0,"add":0,"adFlag":0,"stopWatch":null,"aidSvrType":null,"aidSvrIP":null,"xml":null,"int32TransType":0,"vecDotData":[{"iFlag":1,"uiTime":60000,"iProduct":null,"iAnchor":null,"iPosX":null,"iPosY":null}],"stSourceData":{"iSourceIdType":2,"strSourceId":"w0019cnahya","iUserTypeReq":0,"iVipInfoRsp":1,"iVideoType":-1,"iPayFlag":-1,"iCheckLogin":1,"iCheckUser":1},"iUserType":null,"ullStartTimeStamp":null,"strJson":"{\"adFlag\":0,\"add\":0,\"aid\":\"4021\",\"breakTime\":null,\"breaks\":\"0.0\",\"duration\":325,\"iCheckLogin\":1,\"iCheckUser\":1,\"iUserTypeReq\":0,\"iVipInfoRsp\":1,\"isvip\":0,\"mult\":{\"ivb\":[{\"time\":60000,\"type\":1}]},\"oaid\":\"4021\",\"rfid\":\"c3fc0bf5275a99b194e811fc22677892_1606289057\",\"tm\":1606289057,\"tpid\":106,\"vad\":null,\"vid\":\"w0019cnahya\"}","coverName":null,"videoName":null,"columnName":null,"strVid":"w0019cnahya","labels":[],"stAdtypeData":[],"stSceneDot":[],"uin":0,"extraData":{"tvAdFreeFlag":0},"trytimeSecond":0,"trytimeWithadFlag":null,"strTagSource":null}`
	Rsp := &ad_packet.ResponseFromAdaptor{}
	if err := json.Unmarshal([]byte(data), Rsp); err != nil {
		fmt.Println("fail json.Unmarshal(expect)  err:", err)
		return
	}
	if newJson, err := Rsp.MarshalJSON(); err != nil {
		fmt.Println("fail  err:", err)
		return
	} else {
		fmt.Println(string(newJson))
	}
}
