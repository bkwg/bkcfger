#ifndef BK_TYPES_H
#define BK_TYPES_H

// TODO: add support for other platforms i.e Windows

// Reference: https://sourceforge.net/p/predef/wiki/OperatingSystems/
// Reference: https://sourceforge.net/p/predef/wiki/Compilers/

#if defined(BK_NO_LIBC)
#   if defined(BK_GNUC)
        typedef __UINT8_TYPE__   U8;
        typedef __UINT16_TYPE__  U16;
        typedef __UINT32_TYPE__  U32;
        typedef __UINT64_TYPE__  U64;
        typedef __INT8_TYPE__    I8;
        typedef __INT8_TYPE__    CHAR;
        typedef __INT16_TYPE__   I16;
        typedef __INT32_TYPE__   I32;
        typedef __INT64_TYPE__   I64;
        typedef __SIZE_TYPE__    USize;
        typedef __PTRDIFF_TYPE__ ISize;
        typedef __UINTPTR_TYPE__ UPointer;
        typedef __INTPTR_TYPE__  IPointer;
#   else
#       error "Unsupported compiler for no-libc mode."
#   endif
#else
    // If is libc present, we use stdint types.
#   include <stdint.h>
#   include <stddef.h>
    typedef uint8_t   U8;
    typedef uint16_t  U16;
    typedef uint32_t  U32;
    typedef uint64_t  U64;
    typedef int8_t    I8;
    typedef int8_t    CHAR;
    typedef int16_t   I16;
    typedef int32_t   I32;
    typedef int64_t   I64;
    typedef size_t    USize;
    typedef ptrdiff_t ISize;
    typedef uintptr_t UPointer;
    typedef intptr_t  IPointer;
#endif

typedef U8  BkBool;
typedef U32 BkStatus;

#define BK_TRUE     1
#define BK_FALSE    0

#define BAD 0x80000000
#define BK_CAST_STATUS(x, b) ((BkStatus) (b | x))

#define BK_STATUS_SUCCESS BK_CAST_STATUS(0, 0)
#define BK_STATUS_FAILURE BK_CAST_STATUS(1, BAD)
#define BK_STATUS_BADFILE BK_CAST_STATUS(2, BAD)
#define BK_STATUS_NULLARG BK_CAST_STATUS(3, BAD)
#define BK_STATUS_BADARGS BK_CAST_STATUS(4, BAD)
#define BK_STATUS_TRUE    BK_CAST_STATUS(5, 0)
#define BK_STATUS_FALSE   BK_CAST_STATUS(6, BAD)

#define BK_FAILURE(x) (x & BAD)
#define BK_SUCCESS(x) (!(x & BAD))

#endif
