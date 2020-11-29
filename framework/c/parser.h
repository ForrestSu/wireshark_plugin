#ifndef parser_h
#define parser_h

#include "platform.h"

GO_NS_BEGIN

/* Return type for Parser */
typedef struct StParserReturn {
	const char* msg;
	int64_t len;
}ParserReturn;
/* 封装的C语言字符串 */
typedef struct StCSlice{
    const char* data;
    int32_t len;
}CSlice;

// 解析消息
CSlice call_cgo_parser(CSlice name, CSlice msg);
void call_cgo_free_GoString(CSlice msg);


GO_NS_END

#endif // parser_h