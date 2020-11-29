#ifndef caller_h
#define caller_h

#include <string.h>
#include <stddef.h>
#include <limits.h>

#include "platform.h"

GO_NS_BEGIN

// heap buffer
#define PB_SSO_SIZE (sizeof(pb_HeapBuffer))

typedef struct pb_HeapBuffer {
    unsigned capacity;
    char    *buff;
} pb_HeapBuffer;

typedef struct pb_Buffer {
    unsigned size : sizeof(unsigned)*CHAR_BIT - 1;
    unsigned heap : 1;
    union {
        char buff[PB_SSO_SIZE];
        pb_HeapBuffer h;
    } u;
} pb_Buffer;
#define pb_onheap(b)     ((b)->heap)
#define pb_bufflen(b)    ((b)->size)
#define pb_buffer(b)     (pb_onheap(b) ? (b)->u.h.buff : (b)->u.buff)

// decode
typedef struct pb_Slice { const char *p, *start, *end; } pb_Slice;
GO_API size_t pb_len(const pb_Slice s) { return s.end - s.p; }

GO_API pb_Slice pb_slice  (const char *p);
GO_API pb_Slice pb_lslice (const char *p, size_t len);

// tools
GO_API pb_Slice pb_slice(const char *s)
{ return s ? pb_lslice(s, strlen(s)) : pb_lslice(NULL, 0); }

GO_API pb_Slice pb_result(const pb_Buffer *b)
{ pb_Slice slice = pb_lslice(pb_buffer(b), b->size); return slice; }

GO_API pb_Slice pb_lslice(const char *s, size_t len) {
    pb_Slice slice;
    slice.start = slice.p = s;
    slice.end = s + len;
    return slice;
}

GO_NS_END

#endif
