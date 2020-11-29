#ifndef go_call_h
#define go_call_h

#include "platform.h"

GO_NS_BEGIN

/* 封装的C语言字符串 */
typedef struct ST_CSlice {
    const char* data;
    int32_t len;
} CSlice;

// 解析消息
CSlice call_cgo_parser(CSlice name, CSlice msg);
void call_cgo_free_GoString(CSlice msg);


GO_NS_END

#endif