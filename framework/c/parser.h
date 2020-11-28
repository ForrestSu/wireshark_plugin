#ifndef parser_h
#define parser_h

#ifndef GO_NS_BEGIN
# ifdef __cplusplus
#   define GO_NS_BEGIN extern "C" {
#   define GO_NS_END   }
# else
#   define GO_NS_BEGIN
#   define GO_NS_END
# endif
#endif /* GO_NS_BEGIN */

GO_NS_BEGIN

// 内部调用函数
const char* call_cgo_parser(const char *name_buff, int len1, const char *msg_buff, int len2);

GO_NS_END
#endif