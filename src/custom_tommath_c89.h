/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/*
 * This header defines custom types which
 * are used in c89 mode.
 *
 * By default, the source uses stdbool.h
 * and stdint.h. The command `make c89`
 * can be used to convert the source,
 * such that this header is used instead.
 * Use `make c99` to convert back.
 *
 */

typedef enum { MP_NO, MP_YES } mp_bool;

#if defined(__INT64_TYPE__) && defined(__UINT64_TYPE__)

typedef __INT8_TYPE__       mp_i8;
typedef __INT16_TYPE__      mp_i16;
typedef __INT32_TYPE__      mp_i32;
typedef __INT64_TYPE__      mp_i64;
typedef __UINT8_TYPE__      mp_u8;
typedef __UINT16_TYPE__     mp_u16;
typedef __UINT32_TYPE__     mp_u32;
typedef __UINT64_TYPE__     mp_u64;

#elif defined(_MSC_VER)

typedef __int8              mp_i8;
typedef __int16             mp_i16;
typedef __int32             mp_i32;
typedef __int64             mp_i64;
typedef unsigned __int8     mp_u8;
typedef unsigned __int16    mp_u16;
typedef unsigned __int32    mp_u32;
typedef unsigned __int64    mp_u64;

#else

typedef signed char         mp_i8;
typedef signed short int    mp_i16;
typedef signed int          mp_i32;
typedef signed long long    mp_i64;
typedef unsigned char       mp_u8;
typedef unsigned short int  mp_u16;
typedef unsigned int        mp_u32;
typedef unsigned long long  mp_u64;

#endif
