/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file blake3.c
   BLAKE3 hash, keyed hash and key derivation,
   based on blake3-tiny by Michael Forney (public domain)
   https://github.com/michaelforney/blake3-tiny
*/

#ifdef LTC_BLAKE3

/* Domain-separation flags */
#define BLAKE3_CHUNK_START         (1u << 0)
#define BLAKE3_CHUNK_END           (1u << 1)
#define BLAKE3_PARENT              (1u << 2)
#define BLAKE3_ROOT                (1u << 3)
#define BLAKE3_KEYED_HASH          (1u << 4)
#define BLAKE3_DERIVE_KEY_CONTEXT  (1u << 5)
#define BLAKE3_DERIVE_KEY_MATERIAL (1u << 6)

/* BLAKE3 IV -- same as SHA-256 constants */
static const ulong32 s_iv[8] = { 0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL, 0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL };

/* Load 16 little-endian 32-bit words from a 64-byte buffer */
static void s_load(ulong32 d[16], const unsigned char *s)
{
   int i;
   for (i = 0; i < 16; ++i, s += 4) {
      d[i] =  (ulong32)s[0]
           | ((ulong32)s[1] <<  8)
           | ((ulong32)s[2] << 16)
           | ((ulong32)s[3] << 24);
   }
}

/* Load 8 little-endian 32-bit words from a 32-byte key */
static void s_load_key(ulong32 d[8], const unsigned char *s)
{
   int i;
   for (i = 0; i < 8; ++i, s += 4) {
      d[i] =  (ulong32)s[0]
           | ((ulong32)s[1] <<  8)
           | ((ulong32)s[2] << 16)
           | ((ulong32)s[3] << 24);
   }
}

/* BLAKE3 compression function
   out  - output words (8 always; 16 when BLAKE3_ROOT is set in d)
   m    - 16-word message block (may alias out)
   h    - 8-word chaining value
   t    - chunk counter (64-bit)
   b    - byte count for this block (0-64)
   d    - domain flags
*/
static void s_compress(ulong32 *out, const ulong32 *m, const ulong32 *h, ulong64 t, ulong32 b, ulong32 d)
{
   static const unsigned char s_sigma[7][16] = {
      { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
      { 2,  6,  3, 10,  7,  0,  4, 13,  1, 11, 12,  5,  9, 14, 15,  8},
      { 3,  4, 10, 12, 13,  2,  7, 14,  6,  5,  9,  0, 11, 15,  8,  1},
      {10,  7, 12,  9, 14,  3, 13, 15,  4,  0, 11,  2,  5,  8,  1,  6},
      {12, 13,  9, 11, 15, 10, 14,  8,  7,  2,  5,  3,  0,  1,  6,  4},
      { 9, 14, 11,  5,  8, 12, 15,  1, 13,  3,  0, 10,  2,  6,  4,  7},
      {11, 15,  5,  0,  1,  9,  8,  6, 14, 10,  2, 12,  3,  4,  7, 13},
   };
   ulong32 v[16];
   unsigned int i;

   v[0]  = h[0];    v[1]  = h[1];    v[2]  = h[2];    v[3]  = h[3];
   v[4]  = h[4];    v[5]  = h[5];    v[6]  = h[6];    v[7]  = h[7];
   v[8]  = s_iv[0]; v[9]  = s_iv[1]; v[10] = s_iv[2]; v[11] = s_iv[3];
   v[12] = (ulong32)t;
   v[13] = (ulong32)(t >> 32);
   v[14] = b;
   v[15] = d;

#define B3G(ri, ai, bi, ci, di, mx, my) \
   v[ai] += v[bi] + m[s_sigma[ri][mx]]; \
   v[di]  = RORc(v[di] ^ v[ai], 16); \
   v[ci] += v[di]; \
   v[bi]  = RORc(v[bi] ^ v[ci], 12); \
   v[ai] += v[bi] + m[s_sigma[ri][my]]; \
   v[di]  = RORc(v[di] ^ v[ai],  8); \
   v[ci] += v[di]; \
   v[bi]  = RORc(v[bi] ^ v[ci],  7);

#define B3ROUND(ri) \
   B3G(ri,  0,  4,  8, 12,  0,  1) \
   B3G(ri,  1,  5,  9, 13,  2,  3) \
   B3G(ri,  2,  6, 10, 14,  4,  5) \
   B3G(ri,  3,  7, 11, 15,  6,  7) \
   B3G(ri,  0,  5, 10, 15,  8,  9) \
   B3G(ri,  1,  6, 11, 12, 10, 11) \
   B3G(ri,  2,  7,  8, 13, 12, 13) \
   B3G(ri,  3,  4,  9, 14, 14, 15)

   B3ROUND(0) B3ROUND(1) B3ROUND(2) B3ROUND(3)
   B3ROUND(4) B3ROUND(5) B3ROUND(6)

#undef B3G
#undef B3ROUND

   if (d & BLAKE3_ROOT) {
      for (i = 8; i < 16; ++i) out[i] = v[i] ^ h[i - 8];
   }
   for (i = 0; i < 8; ++i) out[i] = v[i] ^ v[i + 8];
}

/* Process one 64-byte block during update (only called when more data follows, so this block is never the ROOT) */
static void s_blake3_block(hash_state *md, const unsigned char *buf)
{
   ulong32  m[16];
   ulong32 *cv;
   ulong64  t;
   ulong32  flags;

   flags = md->blake3.flags;
   if (md->blake3.block == 0)  flags |= BLAKE3_CHUNK_START;
   if (md->blake3.block == 15) flags |= BLAKE3_CHUNK_END;

   cv = &md->blake3.cv_buf[md->blake3.cv_off * 8u];
   s_load(m, buf);
   s_compress(cv, m, cv, md->blake3.chunk, 64, flags);

   if (++md->blake3.block == 16) {
      md->blake3.block = 0;
      for (t = ++md->blake3.chunk; (t & 1) == 0; t >>= 1) {
         --md->blake3.cv_off;
         cv = &md->blake3.cv_buf[md->blake3.cv_off * 8u];
         s_compress(cv, cv, md->blake3.key, 0, 64, BLAKE3_PARENT | md->blake3.flags);
      }
      ++md->blake3.cv_off;
      cv = &md->blake3.cv_buf[md->blake3.cv_off * 8u];
      XMEMCPY(cv, md->blake3.key, sizeof(md->blake3.key));
   }
}

/**
   Initialize a BLAKE3 hash state (unkeyed hash mode).
   @param md   The hash state to initialize
   @return CRYPT_OK on success
*/
int blake3_init(hash_state *md)
{
   LTC_ARGCHK(md != NULL);
   XMEMSET(&md->blake3, 0, sizeof(md->blake3));
   XMEMCPY(md->blake3.key, s_iv, sizeof(md->blake3.key));
   XMEMCPY(md->blake3.cv_buf, s_iv, sizeof(md->blake3.key));
   return CRYPT_OK;
}

/**
   Initialize a BLAKE3 keyed-hash state (MAC / PRF mode).
   @param md      The hash state to initialize
   @param key     The 32-byte key
   @param keylen  Length of key (must be 32)
   @return CRYPT_OK on success
*/
int blake3_keyed_init(hash_state *md, const unsigned char *key, unsigned long keylen)
{
   LTC_ARGCHK(md  != NULL);
   LTC_ARGCHK(key != NULL);
   if (keylen != 32) return CRYPT_INVALID_KEYSIZE;

   XMEMSET(&md->blake3, 0, sizeof(md->blake3));
   s_load_key(md->blake3.key, key);
   XMEMCPY(md->blake3.cv_buf, md->blake3.key, sizeof(md->blake3.key));
   md->blake3.flags = BLAKE3_KEYED_HASH;
   return CRYPT_OK;
}

/**
   Initialize a BLAKE3 key-derivation state.
   Hashes the context string internally, then prepares the state so that
   subsequent process/done calls derive a key from the input material.
   @param md          The hash state to initialize
   @param context     Application-specific context string
   @param contextlen  Length of the context string in bytes
   @return CRYPT_OK on success
*/
int blake3_derive_key_init(hash_state *md, const unsigned char *context, unsigned long contextlen)
{
   unsigned char context_key[32];
   int err;

   LTC_ARGCHK(md      != NULL);
   LTC_ARGCHK(context != NULL);

   /* Pass 1: hash the context string with DERIVE_KEY_CONTEXT */
   XMEMSET(&md->blake3, 0, sizeof(md->blake3));
   XMEMCPY(md->blake3.key, s_iv, sizeof(md->blake3.key));
   XMEMCPY(md->blake3.cv_buf, s_iv, sizeof(md->blake3.key));
   md->blake3.flags = BLAKE3_DERIVE_KEY_CONTEXT;

   if ((err = blake3_process(md, context, contextlen)) != CRYPT_OK) return err;
   if ((err = blake3_done(md, context_key)) != CRYPT_OK) return err;

   /* Pass 2: set up for key material hashing with DERIVE_KEY_MATERIAL; blake3_done already zeroed the state */
   s_load_key(md->blake3.key, context_key);
   XMEMCPY(md->blake3.cv_buf, md->blake3.key, sizeof(md->blake3.key));
   md->blake3.flags = BLAKE3_DERIVE_KEY_MATERIAL;

   zeromem(context_key, sizeof(context_key));
   return CRYPT_OK;
}

/**
   Process data through BLAKE3.
   @param md     The hash state
   @param in     Data to hash
   @param inlen  Length of data in bytes
   @return CRYPT_OK on success
*/
int blake3_process(hash_state *md, const unsigned char *in, unsigned long inlen)
{
   unsigned long n;

   LTC_ARGCHK(md != NULL);
   LTC_ARGCHK(in != NULL);

   if (md->blake3.bytes > 0) {
      n = 64uL - md->blake3.bytes;
      if (inlen < n) n = inlen;
      XMEMCPY(md->blake3.input + md->blake3.bytes, in, n);
      in    += n;
      inlen -= n;
      md->blake3.bytes += (ulong32)n;
      if (inlen == 0) return CRYPT_OK;
      s_blake3_block(md, md->blake3.input);
   }
   while (inlen > 64) {
      s_blake3_block(md, in);
      in    += 64;
      inlen -= 64;
   }
   md->blake3.bytes = (ulong32)inlen;
   XMEMCPY(md->blake3.input, in, inlen);
   return CRYPT_OK;
}

/**
   Finalize BLAKE3 and produce the 32-byte digest.
   @param md   The hash state
   @param out  [out] 32-byte digest
   @return CRYPT_OK on success
*/
int blake3_done(hash_state *md, unsigned char *out)
{
   ulong32  m[16], root[16];
   ulong32  flags, b, x;
   unsigned long i;

   LTC_ARGCHK(md  != NULL);
   LTC_ARGCHK(out != NULL);

   XMEMSET(md->blake3.input + md->blake3.bytes, 0, 64u - md->blake3.bytes);
   s_load(m, md->blake3.input);

   flags = BLAKE3_CHUNK_END | md->blake3.flags;
   if (md->blake3.block == 0) flags |= BLAKE3_CHUNK_START;

   if (md->blake3.cv_off == 0) {
      b = md->blake3.bytes;
      s_compress(root, m, md->blake3.cv_buf, 0, b, flags | BLAKE3_ROOT);
   }
   else {
      ulong32 *cv = &md->blake3.cv_buf[md->blake3.cv_off * 8u];
      s_compress(cv, m, cv, md->blake3.chunk, md->blake3.bytes, flags);
      while ((cv -= 8) != md->blake3.cv_buf) s_compress(cv, cv, md->blake3.key, 0, 64, BLAKE3_PARENT | md->blake3.flags);
      s_compress(root, md->blake3.cv_buf, md->blake3.key, 0, 64, BLAKE3_PARENT | BLAKE3_ROOT | md->blake3.flags);
   }

   for (i = 0, x = 0; i < 32; ++i) {
      if ((i & 3) == 0) x = root[i >> 2];
      out[i] = (unsigned char)(x & 0xff);
      x >>= 8;
   }

   zeromem(&md->blake3, sizeof(md->blake3));
   return CRYPT_OK;
}

/*
   Self-test with official BLAKE3 test vectors
   https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json

   Input: byte[i] = i % 251.  Key: "whats the Elvish word for friend"
   Context: "BLAKE3 2019-12-27 16:29:52 test vectors context"
*/

int blake3_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   static const struct {
      unsigned long input_len;
      unsigned char hash[32];
      unsigned char keyed_hash[32];
      unsigned char derive_key[32];
   } tests[] = {
      /* input_len = 0 */
      { 0,
         { 0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
           0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62 },
         { 0x92, 0xb2, 0xb7, 0x56, 0x04, 0xed, 0x3c, 0x76, 0x1f, 0x9d, 0x6f, 0x62, 0x39, 0x2c, 0x8a, 0x92,
           0x27, 0xad, 0x0e, 0xa3, 0xf0, 0x95, 0x73, 0xe7, 0x83, 0xf1, 0x49, 0x8a, 0x4e, 0xd6, 0x0d, 0x26 },
         { 0x2c, 0xc3, 0x97, 0x83, 0xc2, 0x23, 0x15, 0x4f, 0xea, 0x8d, 0xfb, 0x7c, 0x1b, 0x16, 0x60, 0xf2,
           0xac, 0x2d, 0xcb, 0xd1, 0xc1, 0xde, 0x82, 0x77, 0xb0, 0xb0, 0xdd, 0x39, 0xb7, 0xe5, 0x0d, 0x7d }
      },
      /* input_len = 1 */
      { 1,
         { 0x2d, 0x3a, 0xde, 0xdf, 0xf1, 0x1b, 0x61, 0xf1, 0x4c, 0x88, 0x6e, 0x35, 0xaf, 0xa0, 0x36, 0x73,
           0x6d, 0xcd, 0x87, 0xa7, 0x4d, 0x27, 0xb5, 0xc1, 0x51, 0x02, 0x25, 0xd0, 0xf5, 0x92, 0xe2, 0x13 },
         { 0x6d, 0x78, 0x78, 0xdf, 0xff, 0x2f, 0x48, 0x56, 0x35, 0xd3, 0x90, 0x13, 0x27, 0x8a, 0xe1, 0x4f,
           0x14, 0x54, 0xb8, 0xc0, 0xa3, 0xa2, 0xd3, 0x4b, 0xc1, 0xab, 0x38, 0x22, 0x8a, 0x80, 0xc9, 0x5b },
         { 0xb3, 0xe2, 0xe3, 0x40, 0xa1, 0x17, 0xa4, 0x99, 0xc6, 0xcf, 0x23, 0x98, 0xa1, 0x9e, 0xe0, 0xd2,
           0x9c, 0xca, 0x2b, 0xb7, 0x40, 0x4c, 0x73, 0x06, 0x33, 0x82, 0x69, 0x3b, 0xf6, 0x6c, 0xb0, 0x6c }
      },
      /* input_len = 65 */
      { 65,
         { 0xde, 0x1e, 0x5f, 0xa0, 0xbe, 0x70, 0xdf, 0x6d, 0x2b, 0xe8, 0xff, 0xfd, 0x0e, 0x99, 0xce, 0xaa,
           0x8e, 0xb6, 0xe8, 0xc9, 0x3a, 0x63, 0xf2, 0xd8, 0xd1, 0xc3, 0x0e, 0xcb, 0x6b, 0x26, 0x3d, 0xee },
         { 0xc0, 0xa4, 0xed, 0xef, 0xa2, 0xd2, 0xac, 0xcb, 0x92, 0x77, 0xc3, 0x71, 0xac, 0x12, 0xfc, 0xdb,
           0xb5, 0x29, 0x88, 0xa8, 0x6e, 0xdc, 0x54, 0xf0, 0x71, 0x6e, 0x15, 0x91, 0xb4, 0x32, 0x6e, 0x72 },
         { 0x51, 0xfd, 0x05, 0xc3, 0xc1, 0xcf, 0xbc, 0x8e, 0xd6, 0x7d, 0x13, 0x9a, 0xd7, 0x6f, 0x5c, 0xf8,
           0x23, 0x6c, 0xd2, 0xac, 0xd2, 0x66, 0x27, 0xa3, 0x0c, 0x10, 0x4d, 0xfd, 0x9d, 0x3f, 0xf8, 0xa8 }
      },
      /* input_len = 1024 (single chunk boundary) */
      { 1024,
         { 0x42, 0x21, 0x47, 0x39, 0xf0, 0x95, 0xa4, 0x06, 0xf3, 0xfc, 0x83, 0xde, 0xb8, 0x89, 0x74, 0x4a,
           0xc0, 0x0d, 0xf8, 0x31, 0xc1, 0x0d, 0xaa, 0x55, 0x18, 0x9b, 0x5d, 0x12, 0x1c, 0x85, 0x5a, 0xf7 },
         { 0x75, 0xc4, 0x6f, 0x6f, 0x3d, 0x9e, 0xb4, 0xf5, 0x5e, 0xca, 0xae, 0xe4, 0x80, 0xdb, 0x73, 0x2e,
           0x6c, 0x21, 0x05, 0x54, 0x6f, 0x1e, 0x67, 0x50, 0x03, 0x68, 0x7c, 0x31, 0x71, 0x9c, 0x7b, 0xa4 },
         { 0x73, 0x56, 0xcd, 0x77, 0x20, 0xd5, 0xb6, 0x6b, 0x6d, 0x06, 0x97, 0xeb, 0x31, 0x77, 0xd9, 0xf8,
           0xd7, 0x3a, 0x4a, 0x5c, 0x5e, 0x96, 0x88, 0x96, 0xeb, 0x6a, 0x68, 0x96, 0x84, 0x30, 0x27, 0x06 }
      },
      /* input_len = 1025 (multi-chunk) */
      { 1025,
         { 0xd0, 0x02, 0x78, 0xae, 0x47, 0xeb, 0x27, 0xb3, 0x4f, 0xae, 0xcf, 0x67, 0xb4, 0xfe, 0x26, 0x3f,
           0x82, 0xd5, 0x41, 0x29, 0x16, 0xc1, 0xff, 0xd9, 0x7c, 0x8c, 0xb7, 0xfb, 0x81, 0x4b, 0x84, 0x44 },
         { 0x35, 0x7d, 0xc5, 0x5d, 0xe0, 0xc7, 0xe3, 0x82, 0xc9, 0x00, 0xfd, 0x6e, 0x32, 0x0a, 0xcc, 0x04,
           0x14, 0x6b, 0xe0, 0x1d, 0xb6, 0xa8, 0xce, 0x72, 0x10, 0xb7, 0x18, 0x9b, 0xd6, 0x64, 0xea, 0x69 },
         { 0xef, 0xfa, 0xa2, 0x45, 0xf0, 0x65, 0xfb, 0xf8, 0x2a, 0xc1, 0x86, 0x83, 0x9a, 0x24, 0x97, 0x07,
           0xc3, 0xbd, 0xdf, 0x6d, 0x3f, 0xdd, 0xa2, 0x2d, 0x1b, 0x95, 0xa3, 0xc9, 0x70, 0x37, 0x9b, 0xcb }
      },
   };

   static const unsigned char test_key[32] = "whats the Elvish word for friend";
   static const char test_context[] = "BLAKE3 2019-12-27 16:29:52 test vectors context";
   unsigned char input[1025], tmp[32];
   hash_state md;
   unsigned long j;
   int i;

   /* Build test input: byte[i] = i % 251 */
   for (j = 0; j < sizeof(input); ++j) input[j] = (unsigned char)(j % 251);

   for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); ++i) {
      /* hash mode */
      blake3_init(&md);
      blake3_process(&md, input, tests[i].input_len);
      blake3_done(&md, tmp);
      if (ltc_compare_testvector(tmp, 32, tests[i].hash, 32, "BLAKE3", i)) return CRYPT_FAIL_TESTVECTOR;
      /* keyed_hash mode */
      blake3_keyed_init(&md, test_key, 32);
      blake3_process(&md, input, tests[i].input_len);
      blake3_done(&md, tmp);
      if (ltc_compare_testvector(tmp, 32, tests[i].keyed_hash, 32, "BLAKE3 keyed", i)) return CRYPT_FAIL_TESTVECTOR;
      /* derive_key mode */
      blake3_derive_key_init(&md, (const unsigned char *)test_context, XSTRLEN(test_context));
      blake3_process(&md, input, tests[i].input_len);
      blake3_done(&md, tmp);
      if (ltc_compare_testvector(tmp, 32, tests[i].derive_key, 32, "BLAKE3 derive_key", i)) return CRYPT_FAIL_TESTVECTOR;
   }
   return CRYPT_OK;
#endif
}

const struct ltc_hash_descriptor blake3_desc = {
   "blake3",
   37,          /* unique internal ID */
   32,          /* 256-bit digest */
   64,          /* 64-byte input block */
   { 0 }, 0,    /* no ASN.1 OID assigned yet */
   &blake3_init,
   &blake3_process,
   &blake3_done,
   &blake3_test,
   NULL
};

#endif /* LTC_BLAKE3 */
