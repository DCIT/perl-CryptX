/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file sm3.c
   SM3 hash function (GM/T 0004-2012)

   Based on the Crypto++ implementation by Jeffrey Walton and Han Lulu,
   which was placed in the public domain.
   Also see https://tools.ietf.org/html/draft-shen-sm3-hash
*/

#ifdef LTC_SM3

const struct ltc_hash_descriptor sm3_desc =
{
   "sm3",                  /* name of hash */
   34,                     /* internal ID */
   32,                     /* Size of digest in octets */
   64,                     /* Input block size in octets */
   {1,2,156,10197,1,401},  /* ASN.1 OID 1.2.156.10197.1.401 */
   6,                      /* Length OID */
   &sm3_init,
   &sm3_process,
   &sm3_done,
   &sm3_test,
   NULL
};

/* Permutation functions */
static LTC_INLINE ulong32 s_sm3_P0(ulong32 X)
{
   return X ^ ROLc(X, 9) ^ ROLc(X, 17);
}

static LTC_INLINE ulong32 s_sm3_P1(ulong32 X)
{
   return X ^ ROLc(X, 15) ^ ROLc(X, 23);
}

/* Message expansion */
static LTC_INLINE ulong32 s_sm3_EE(ulong32 W0, ulong32 W7, ulong32 W13, ulong32 W3, ulong32 W10)
{
   return s_sm3_P1(W0 ^ W7 ^ ROLc(W13, 15)) ^ ROLc(W3, 7) ^ W10;
}

/* Boolean functions for rounds 0-15 */
#define FF0(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define GG0(X, Y, Z) ((X) ^ (Y) ^ (Z))

/* Boolean functions for rounds 16-63 */
#define FF1(X, Y, Z) (((X) & (Y)) | (((X) | (Y)) & (Z)))
#define GG1(X, Y, Z) ((Z) ^ ((X) & ((Y) ^ (Z))))

/* Round function for rounds 0-15 */
#define R1(A, B, C, D, E, F, G, H, TJ, Wi, Wj) do {                   \
   const ulong32 A12 = ROLc((A), 12);                                 \
   const ulong32 TT0 = ROLc(A12 + (E) + (TJ), 7);                     \
   const ulong32 TT1 = FF0((A), (B), (C)) + (D) + (TT0 ^ A12) + (Wj); \
   const ulong32 TT2 = GG0((E), (F), (G)) + (H) + TT0 + (Wi);         \
   (B) = ROLc((B), 9);                                                \
   (D) = TT1;                                                         \
   (F) = ROLc((F), 19);                                               \
   (H) = s_sm3_P0(TT2);                                               \
} while(0)

/* Round function for rounds 16-63 */
#define R2(A, B, C, D, E, F, G, H, TJ, Wi, Wj) do {                   \
   const ulong32 A12 = ROLc((A), 12);                                 \
   const ulong32 TT0 = ROLc(A12 + (E) + (TJ), 7);                     \
   const ulong32 TT1 = FF1((A), (B), (C)) + (D) + (TT0 ^ A12) + (Wj); \
   const ulong32 TT2 = GG1((E), (F), (G)) + (H) + TT0 + (Wi);         \
   (B) = ROLc((B), 9);                                                \
   (D) = TT1;                                                         \
   (F) = ROLc((F), 19);                                               \
   (H) = s_sm3_P0(TT2);                                               \
} while(0)

static int  s_sm3_compress(hash_state *md, const unsigned char *buf)
{
   ulong32 A, B, C, D, E, F, G, H;
   ulong32 W00, W01, W02, W03, W04, W05, W06, W07;
   ulong32 W08, W09, W10, W11, W12, W13, W14, W15;

   /* load state */
   A = md->sm3.state[0];
   B = md->sm3.state[1];
   C = md->sm3.state[2];
   D = md->sm3.state[3];
   E = md->sm3.state[4];
   F = md->sm3.state[5];
   G = md->sm3.state[6];
   H = md->sm3.state[7];

   /* load message block (big-endian) */
   LOAD32H(W00, buf +  0); LOAD32H(W01, buf +  4);
   LOAD32H(W02, buf +  8); LOAD32H(W03, buf + 12);
   LOAD32H(W04, buf + 16); LOAD32H(W05, buf + 20);
   LOAD32H(W06, buf + 24); LOAD32H(W07, buf + 28);
   LOAD32H(W08, buf + 32); LOAD32H(W09, buf + 36);
   LOAD32H(W10, buf + 40); LOAD32H(W11, buf + 44);
   LOAD32H(W12, buf + 48); LOAD32H(W13, buf + 52);
   LOAD32H(W14, buf + 56); LOAD32H(W15, buf + 60);

   /* rounds 0-15 (R1) */
   R1(A, B, C, D, E, F, G, H, 0x79CC4519UL, W00, W00 ^ W04);
   W00 = s_sm3_EE(W00, W07, W13, W03, W10);
   R1(D, A, B, C, H, E, F, G, 0xF3988A32UL, W01, W01 ^ W05);
   W01 = s_sm3_EE(W01, W08, W14, W04, W11);
   R1(C, D, A, B, G, H, E, F, 0xE7311465UL, W02, W02 ^ W06);
   W02 = s_sm3_EE(W02, W09, W15, W05, W12);
   R1(B, C, D, A, F, G, H, E, 0xCE6228CBUL, W03, W03 ^ W07);
   W03 = s_sm3_EE(W03, W10, W00, W06, W13);
   R1(A, B, C, D, E, F, G, H, 0x9CC45197UL, W04, W04 ^ W08);
   W04 = s_sm3_EE(W04, W11, W01, W07, W14);
   R1(D, A, B, C, H, E, F, G, 0x3988A32FUL, W05, W05 ^ W09);
   W05 = s_sm3_EE(W05, W12, W02, W08, W15);
   R1(C, D, A, B, G, H, E, F, 0x7311465EUL, W06, W06 ^ W10);
   W06 = s_sm3_EE(W06, W13, W03, W09, W00);
   R1(B, C, D, A, F, G, H, E, 0xE6228CBCUL, W07, W07 ^ W11);
   W07 = s_sm3_EE(W07, W14, W04, W10, W01);
   R1(A, B, C, D, E, F, G, H, 0xCC451979UL, W08, W08 ^ W12);
   W08 = s_sm3_EE(W08, W15, W05, W11, W02);
   R1(D, A, B, C, H, E, F, G, 0x988A32F3UL, W09, W09 ^ W13);
   W09 = s_sm3_EE(W09, W00, W06, W12, W03);
   R1(C, D, A, B, G, H, E, F, 0x311465E7UL, W10, W10 ^ W14);
   W10 = s_sm3_EE(W10, W01, W07, W13, W04);
   R1(B, C, D, A, F, G, H, E, 0x6228CBCEUL, W11, W11 ^ W15);
   W11 = s_sm3_EE(W11, W02, W08, W14, W05);
   R1(A, B, C, D, E, F, G, H, 0xC451979CUL, W12, W12 ^ W00);
   W12 = s_sm3_EE(W12, W03, W09, W15, W06);
   R1(D, A, B, C, H, E, F, G, 0x88A32F39UL, W13, W13 ^ W01);
   W13 = s_sm3_EE(W13, W04, W10, W00, W07);
   R1(C, D, A, B, G, H, E, F, 0x11465E73UL, W14, W14 ^ W02);
   W14 = s_sm3_EE(W14, W05, W11, W01, W08);
   R1(B, C, D, A, F, G, H, E, 0x228CBCE6UL, W15, W15 ^ W03);
   W15 = s_sm3_EE(W15, W06, W12, W02, W09);

   /* rounds 16-63 (R2) */
   R2(A, B, C, D, E, F, G, H, 0x9D8A7A87UL, W00, W00 ^ W04);
   W00 = s_sm3_EE(W00, W07, W13, W03, W10);
   R2(D, A, B, C, H, E, F, G, 0x3B14F50FUL, W01, W01 ^ W05);
   W01 = s_sm3_EE(W01, W08, W14, W04, W11);
   R2(C, D, A, B, G, H, E, F, 0x7629EA1EUL, W02, W02 ^ W06);
   W02 = s_sm3_EE(W02, W09, W15, W05, W12);
   R2(B, C, D, A, F, G, H, E, 0xEC53D43CUL, W03, W03 ^ W07);
   W03 = s_sm3_EE(W03, W10, W00, W06, W13);
   R2(A, B, C, D, E, F, G, H, 0xD8A7A879UL, W04, W04 ^ W08);
   W04 = s_sm3_EE(W04, W11, W01, W07, W14);
   R2(D, A, B, C, H, E, F, G, 0xB14F50F3UL, W05, W05 ^ W09);
   W05 = s_sm3_EE(W05, W12, W02, W08, W15);
   R2(C, D, A, B, G, H, E, F, 0x629EA1E7UL, W06, W06 ^ W10);
   W06 = s_sm3_EE(W06, W13, W03, W09, W00);
   R2(B, C, D, A, F, G, H, E, 0xC53D43CEUL, W07, W07 ^ W11);
   W07 = s_sm3_EE(W07, W14, W04, W10, W01);
   R2(A, B, C, D, E, F, G, H, 0x8A7A879DUL, W08, W08 ^ W12);
   W08 = s_sm3_EE(W08, W15, W05, W11, W02);
   R2(D, A, B, C, H, E, F, G, 0x14F50F3BUL, W09, W09 ^ W13);
   W09 = s_sm3_EE(W09, W00, W06, W12, W03);
   R2(C, D, A, B, G, H, E, F, 0x29EA1E76UL, W10, W10 ^ W14);
   W10 = s_sm3_EE(W10, W01, W07, W13, W04);
   R2(B, C, D, A, F, G, H, E, 0x53D43CECUL, W11, W11 ^ W15);
   W11 = s_sm3_EE(W11, W02, W08, W14, W05);
   R2(A, B, C, D, E, F, G, H, 0xA7A879D8UL, W12, W12 ^ W00);
   W12 = s_sm3_EE(W12, W03, W09, W15, W06);
   R2(D, A, B, C, H, E, F, G, 0x4F50F3B1UL, W13, W13 ^ W01);
   W13 = s_sm3_EE(W13, W04, W10, W00, W07);
   R2(C, D, A, B, G, H, E, F, 0x9EA1E762UL, W14, W14 ^ W02);
   W14 = s_sm3_EE(W14, W05, W11, W01, W08);
   R2(B, C, D, A, F, G, H, E, 0x3D43CEC5UL, W15, W15 ^ W03);
   W15 = s_sm3_EE(W15, W06, W12, W02, W09);

   R2(A, B, C, D, E, F, G, H, 0x7A879D8AUL, W00, W00 ^ W04);
   W00 = s_sm3_EE(W00, W07, W13, W03, W10);
   R2(D, A, B, C, H, E, F, G, 0xF50F3B14UL, W01, W01 ^ W05);
   W01 = s_sm3_EE(W01, W08, W14, W04, W11);
   R2(C, D, A, B, G, H, E, F, 0xEA1E7629UL, W02, W02 ^ W06);
   W02 = s_sm3_EE(W02, W09, W15, W05, W12);
   R2(B, C, D, A, F, G, H, E, 0xD43CEC53UL, W03, W03 ^ W07);
   W03 = s_sm3_EE(W03, W10, W00, W06, W13);
   R2(A, B, C, D, E, F, G, H, 0xA879D8A7UL, W04, W04 ^ W08);
   W04 = s_sm3_EE(W04, W11, W01, W07, W14);
   R2(D, A, B, C, H, E, F, G, 0x50F3B14FUL, W05, W05 ^ W09);
   W05 = s_sm3_EE(W05, W12, W02, W08, W15);
   R2(C, D, A, B, G, H, E, F, 0xA1E7629EUL, W06, W06 ^ W10);
   W06 = s_sm3_EE(W06, W13, W03, W09, W00);
   R2(B, C, D, A, F, G, H, E, 0x43CEC53DUL, W07, W07 ^ W11);
   W07 = s_sm3_EE(W07, W14, W04, W10, W01);
   R2(A, B, C, D, E, F, G, H, 0x879D8A7AUL, W08, W08 ^ W12);
   W08 = s_sm3_EE(W08, W15, W05, W11, W02);
   R2(D, A, B, C, H, E, F, G, 0x0F3B14F5UL, W09, W09 ^ W13);
   W09 = s_sm3_EE(W09, W00, W06, W12, W03);
   R2(C, D, A, B, G, H, E, F, 0x1E7629EAUL, W10, W10 ^ W14);
   W10 = s_sm3_EE(W10, W01, W07, W13, W04);
   R2(B, C, D, A, F, G, H, E, 0x3CEC53D4UL, W11, W11 ^ W15);
   W11 = s_sm3_EE(W11, W02, W08, W14, W05);
   R2(A, B, C, D, E, F, G, H, 0x79D8A7A8UL, W12, W12 ^ W00);
   W12 = s_sm3_EE(W12, W03, W09, W15, W06);
   R2(D, A, B, C, H, E, F, G, 0xF3B14F50UL, W13, W13 ^ W01);
   W13 = s_sm3_EE(W13, W04, W10, W00, W07);
   R2(C, D, A, B, G, H, E, F, 0xE7629EA1UL, W14, W14 ^ W02);
   W14 = s_sm3_EE(W14, W05, W11, W01, W08);
   R2(B, C, D, A, F, G, H, E, 0xCEC53D43UL, W15, W15 ^ W03);
   W15 = s_sm3_EE(W15, W06, W12, W02, W09);

   R2(A, B, C, D, E, F, G, H, 0x9D8A7A87UL, W00, W00 ^ W04);
   W00 = s_sm3_EE(W00, W07, W13, W03, W10);
   R2(D, A, B, C, H, E, F, G, 0x3B14F50FUL, W01, W01 ^ W05);
   W01 = s_sm3_EE(W01, W08, W14, W04, W11);
   R2(C, D, A, B, G, H, E, F, 0x7629EA1EUL, W02, W02 ^ W06);
   W02 = s_sm3_EE(W02, W09, W15, W05, W12);
   R2(B, C, D, A, F, G, H, E, 0xEC53D43CUL, W03, W03 ^ W07);
   W03 = s_sm3_EE(W03, W10, W00, W06, W13);
   R2(A, B, C, D, E, F, G, H, 0xD8A7A879UL, W04, W04 ^ W08);
   R2(D, A, B, C, H, E, F, G, 0xB14F50F3UL, W05, W05 ^ W09);
   R2(C, D, A, B, G, H, E, F, 0x629EA1E7UL, W06, W06 ^ W10);
   R2(B, C, D, A, F, G, H, E, 0xC53D43CEUL, W07, W07 ^ W11);
   R2(A, B, C, D, E, F, G, H, 0x8A7A879DUL, W08, W08 ^ W12);
   R2(D, A, B, C, H, E, F, G, 0x14F50F3BUL, W09, W09 ^ W13);
   R2(C, D, A, B, G, H, E, F, 0x29EA1E76UL, W10, W10 ^ W14);
   R2(B, C, D, A, F, G, H, E, 0x53D43CECUL, W11, W11 ^ W15);
   R2(A, B, C, D, E, F, G, H, 0xA7A879D8UL, W12, W12 ^ W00);
   R2(D, A, B, C, H, E, F, G, 0x4F50F3B1UL, W13, W13 ^ W01);
   R2(C, D, A, B, G, H, E, F, 0x9EA1E762UL, W14, W14 ^ W02);
   R2(B, C, D, A, F, G, H, E, 0x3D43CEC5UL, W15, W15 ^ W03);

   /* feedback */
   md->sm3.state[0] ^= A;
   md->sm3.state[1] ^= B;
   md->sm3.state[2] ^= C;
   md->sm3.state[3] ^= D;
   md->sm3.state[4] ^= E;
   md->sm3.state[5] ^= F;
   md->sm3.state[6] ^= G;
   md->sm3.state[7] ^= H;

   return CRYPT_OK;
}

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sm3_init(hash_state * md)
{
   LTC_ARGCHK(md != NULL);
   md->sm3.state[0] = 0x7380166FUL;
   md->sm3.state[1] = 0x4914B2B9UL;
   md->sm3.state[2] = 0x172442D7UL;
   md->sm3.state[3] = 0xDA8A0600UL;
   md->sm3.state[4] = 0xA96F30BCUL;
   md->sm3.state[5] = 0x163138AAUL;
   md->sm3.state[6] = 0xE38DEE4DUL;
   md->sm3.state[7] = 0xB0FB0E4EUL;
   md->sm3.curlen   = 0;
   md->sm3.length   = 0;
   return CRYPT_OK;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
HASH_PROCESS(sm3_process, s_sm3_compress, sm3, 64)

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (32 bytes)
   @return CRYPT_OK if successful
*/
int sm3_done(hash_state * md, unsigned char *out)
{
    int i;

    LTC_ARGCHK(md  != NULL);
    LTC_ARGCHK(out != NULL);

    if (md->sm3.curlen >= sizeof(md->sm3.buf)) {
       return CRYPT_INVALID_ARG;
    }

    /* increase the length of the message */
    md->sm3.length += md->sm3.curlen * 8;

    /* append the '1' bit */
    md->sm3.buf[md->sm3.curlen++] = (unsigned char)0x80;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->sm3.curlen > 56) {
        while (md->sm3.curlen < 64) {
            md->sm3.buf[md->sm3.curlen++] = (unsigned char)0;
        }
        s_sm3_compress(md, md->sm3.buf);
        md->sm3.curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->sm3.curlen < 56) {
        md->sm3.buf[md->sm3.curlen++] = (unsigned char)0;
    }

    /* store length (big-endian) */
    STORE64H(md->sm3.length, md->sm3.buf+56);
    s_sm3_compress(md, md->sm3.buf);

    /* copy output (big-endian) */
    for (i = 0; i < 8; i++) {
        STORE32H(md->sm3.state[i], out+(4*i));
    }
    return CRYPT_OK;
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int sm3_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   static const struct {
       const char *msg;
       unsigned char hash[32];
   } tests[] = {
   /* Example 1 from the SM3 specification (GM/T 0004-2012) */
   { "abc",
     { 0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
       0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
       0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
       0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0 }
   },
   /* Example 2 from the SM3 specification (GM/T 0004-2012) */
   { "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
     { 0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1,
       0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
       0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65,
       0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32 }
   },
   /* Additional test vectors generated by `openssl dgst -sm3` (OpenSSL 3.0.13) */
   { "",
     { 0x1a, 0xb2, 0x1d, 0x83, 0x55, 0xcf, 0xa1, 0x7f,
       0x8e, 0x61, 0x19, 0x48, 0x31, 0xe8, 0x1a, 0x8f,
       0x22, 0xbe, 0xc8, 0xc7, 0x28, 0xfe, 0xfb, 0x74,
       0x7e, 0xd0, 0x35, 0xeb, 0x50, 0x82, 0xaa, 0x2b }
   },
   { "a",
     { 0x62, 0x34, 0x76, 0xac, 0x18, 0xf6, 0x5a, 0x29,
       0x09, 0xe4, 0x3c, 0x7f, 0xec, 0x61, 0xb4, 0x9c,
       0x7e, 0x76, 0x4a, 0x91, 0xa1, 0x8c, 0xcb, 0x82,
       0xf1, 0x91, 0x7a, 0x29, 0xc8, 0x6c, 0x5e, 0x88 }
   },
   { "abcdefghijklmnopqrstuvwxyz",
     { 0xb8, 0x0f, 0xe9, 0x7a, 0x4d, 0xa2, 0x4a, 0xfc,
       0x27, 0x75, 0x64, 0xf6, 0x6a, 0x35, 0x9e, 0xf4,
       0x40, 0x46, 0x2a, 0xd2, 0x8d, 0xcc, 0x6d, 0x63,
       0xad, 0xb2, 0x4d, 0x5c, 0x20, 0xa6, 0x15, 0x95 }
   },
   { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
     { 0x29, 0x71, 0xd1, 0x0c, 0x88, 0x42, 0xb7, 0x0c,
       0x97, 0x9e, 0x55, 0x06, 0x34, 0x80, 0xc5, 0x0b,
       0xac, 0xff, 0xd9, 0x0e, 0x98, 0xe2, 0xe6, 0x0d,
       0x25, 0x12, 0xab, 0x8a, 0xbf, 0xdf, 0xce, 0xc5 }
   },
   { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     { 0x28, 0x83, 0x37, 0xee, 0xf5, 0x1e, 0xec, 0x62,
       0xe7, 0x54, 0x4d, 0x72, 0x70, 0x42, 0x4c, 0x8d,
       0xbe, 0x65, 0x62, 0x54, 0xc9, 0x98, 0x52, 0x87,
       0x0a, 0x73, 0xb2, 0x45, 0x3a, 0x6a, 0x7f, 0xb1 }
   },
   { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     { 0xba, 0x00, 0xeb, 0xed, 0xaa, 0xb5, 0x40, 0x65,
       0xa5, 0xfd, 0x4f, 0x9f, 0x56, 0x32, 0x60, 0x16,
       0x20, 0x31, 0x66, 0xbc, 0xee, 0x3e, 0xed, 0x44,
       0xea, 0x86, 0x8d, 0x59, 0xd6, 0x7a, 0xa3, 0xc8 }
   },
   { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     { 0x58, 0x73, 0x08, 0x54, 0x35, 0x51, 0x88, 0x1e,
       0xbd, 0x70, 0xd2, 0x7a, 0xd3, 0x58, 0xff, 0x5d,
       0xcd, 0xf2, 0x4a, 0xc5, 0x48, 0x22, 0xe2, 0xf7,
       0xb7, 0xc3, 0xed, 0xce, 0x09, 0x85, 0xd2, 0x1b }
   },
   { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     { 0x61, 0x6e, 0xc4, 0x33, 0xc3, 0x59, 0xe7, 0xc2,
       0xb1, 0x9f, 0x36, 0x0e, 0x2b, 0x8f, 0x2a, 0x1b,
       0x6e, 0x9e, 0xd7, 0x6b, 0x8d, 0xc1, 0xa7, 0xd2,
       0x07, 0xb3, 0x1a, 0x53, 0x41, 0xc6, 0x11, 0xe9 }
   }
   };

   int i;
   unsigned char tmp[32];
   hash_state md;

   for (i = 0; i < (int)LTC_ARRAY_SIZE(tests); i++) {
       sm3_init(&md);
       sm3_process(&md, (const unsigned char *)tests[i].msg, XSTRLEN(tests[i].msg));
       sm3_done(&md, tmp);
       if (ltc_compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), "SM3", i)) {
          return CRYPT_FAIL_TESTVECTOR;
       }
   }
   return CRYPT_OK;
#endif
}

#undef FF0
#undef GG0
#undef FF1
#undef GG1
#undef R1
#undef R2

#endif
