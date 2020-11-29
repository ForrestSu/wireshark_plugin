#include <stdio.h>

#include "cgo_call.h"
#include "../build/libparser.h"

CSlice call_cgo_parser(CSlice name, CSlice msg) {
     // params
    GoString goName;
    goName.p = name.data;
    goName.n = (int64_t)name.len;

    GoString goMsg;
    goMsg.p = msg.data;
    goMsg.n = (int64_t)msg.len;
    // call
    GoString ret = Parse(goName, goMsg);
    // don't forget free GoString(ret.p0)
    CSlice sli = {ret.p, ret.n};
    return sli;
}

void call_cgo_free_GoString(CSlice msg) {
    if (msg.data != NULL) {
        // printf("free GoString line = %d, msg = <%s>.\n", msg.len, msg.data);
        FreeGoString((char*)(msg.data));
    }
}
