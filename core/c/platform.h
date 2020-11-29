#ifndef platform_h
#define platform_h

#ifndef GO_NS_BEGIN
# ifdef __cplusplus
#   define GO_NS_BEGIN extern "C" {
#   define GO_NS_END   }
# else
#   define GO_NS_BEGIN
#   define GO_NS_END
# endif
#endif /* GO_NS_BEGIN */


#ifndef GO_API
# define GO_API extern
#endif

#endif