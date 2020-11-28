#include <stdio.h>
#include "parser.h"
#include "../build/libparser.h"

const char *call_cgo_parse(const char *name_buff, int len1, const char *msg_buff, int len2)
{
     // params
    GoString goName;
    goName.p = name_buff;
    goName.n = (int64_t)len1;

    GoString goMsg;
    goMsg.p = msg_buff;
    goMsg.n = (int64_t)len2;
    // call
    const char *cgo_ptr = Parser(goName, goMsg);
    // TODO don't forget free(cgo_ptr)
    return cgo_ptr;
}