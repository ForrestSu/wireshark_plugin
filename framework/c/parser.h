#ifndef parser_h
#define parser_h

#include "platform.h"

GO_NS_BEGIN

// 内部调用函数
const char* call_cgo_parser(const char *name_buff, int len1, const char *msg_buff, int len2);

GO_NS_END

#endif // parser_h