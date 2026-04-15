/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file scrypt.c
   scrypt password-based key derivation function (RFC 7914)
*/
#ifdef LTC_SCRYPT

/* Salsa20/8 Core (RFC 7914 Section 3) */
#define SCRYPT_QR(a,b,c,d) \
   x[b] ^= ROL(x[a] + x[d],  7); \
   x[c] ^= ROL(x[b] + x[a],  9); \
   x[d] ^= ROL(x[c] + x[b], 13); \
   x[a] ^= ROL(x[d] + x[c], 18);

static void s_salsa20_8(unsigned char B[64])
{
   ulong32 x[16], b32[16];
   int i;

   for (i = 0; i < 16; ++i) {
      LOAD32L(b32[i], B + i * 4);
   }
   XMEMCPY(x, b32, sizeof(x));
   for (i = 8; i > 0; i -= 2) {
      SCRYPT_QR( 0, 4, 8,12)
      SCRYPT_QR( 5, 9,13, 1)
      SCRYPT_QR(10,14, 2, 6)
      SCRYPT_QR(15, 3, 7,11)
      SCRYPT_QR( 0, 1, 2, 3)
      SCRYPT_QR( 5, 6, 7, 4)
      SCRYPT_QR(10,11, 8, 9)
      SCRYPT_QR(15,12,13,14)
   }
   for (i = 0; i < 16; ++i) {
      STORE32L(x[i] + b32[i], B + i * 4);
   }
}

/* scryptBlockMix (RFC 7914 Section 4) */
static void s_blockmix(unsigned char *B, unsigned char *Y, unsigned long r)
{
   unsigned char X[64];
   unsigned long i;
   unsigned long blen = 128 * r;

   /* 1: X = B[2r - 1] */
   XMEMCPY(X, B + blen - 64, 64);
   /* 2: for i = 0 to 2r-1 */
   for (i = 0; i < 2 * r; ++i) {
      unsigned long j;
      for (j = 0; j < 64; ++j) X[j] ^= B[i * 64 + j];
      s_salsa20_8(X);
      XMEMCPY(Y + i * 64, X, 64);
   }
   /* 3: B' = (Y[0], Y[2], ..., Y[2r-2], Y[1], Y[3], ..., Y[2r-1]) */
   for (i = 0; i < r; ++i) {
      XMEMCPY(B + i * 64, Y + (2 * i) * 64, 64);
   }
   for (i = 0; i < r; ++i) {
      XMEMCPY(B + (i + r) * 64, Y + (2 * i + 1) * 64, 64);
   }
}

/* Integerify: interpret last 64-byte block as little-endian and return low 64 bits */
static LTC_INLINE ulong64 s_integerify(const unsigned char *B, unsigned long r)
{
   const unsigned char *X = B + (2 * r - 1) * 64;
   ulong64 v;

   LOAD64L(v, X);
   return v;
}

/* scryptROMix (RFC 7914 Section 5) */
static void s_romix(unsigned char *B, unsigned long r, ulong64 N, unsigned char *V, unsigned char *XY)
{
   unsigned char *X = XY;
   unsigned char *Y = XY + 128 * r;
   unsigned long blen = 128 * r;
   ulong64 i, j;

   /* 1: X = B */
   XMEMCPY(X, B, blen);
   /* 2: for i = 0 to N-1: V[i] = X; X = BlockMix(X) */
   for (i = 0; i < N; ++i) {
      XMEMCPY(V + i * blen, X, blen);
      s_blockmix(X, Y, r);
   }
   /* 3: for i = 0 to N-1 */
   for (i = 0; i < N; ++i) {
      j = s_integerify(X, r) & (N - 1);
      {
         unsigned long k;
         unsigned char *Vj = V + j * blen;
         for (k = 0; k < blen; ++k) X[k] ^= Vj[k];
      }
      s_blockmix(X, Y, r);
   }
   /* 4: B' = X */
   XMEMCPY(B, X, blen);
}

/**
   Derive a key using scrypt (RFC 7914)

   @param password       Password
   @param password_len   Length of password
   @param salt           Salt
   @param salt_len       Length of salt
   @param N              CPU/memory cost parameter (must be > 1 and a power of 2)
   @param r              Block size parameter (minimum 1)
   @param p              Parallelisation parameter (minimum 1)
   @param out            [out] Derived key
   @param outlen         Desired output length
   @return CRYPT_OK on success
*/
int scrypt_pbkdf(const unsigned char *password, unsigned long password_len,
                 const unsigned char *salt,     unsigned long salt_len,
                 unsigned long N, unsigned long r, unsigned long p,
                 unsigned char *out, unsigned long outlen)
{
   unsigned char *B = NULL, *V = NULL, *XY = NULL;
   const unsigned char *pwd;
   unsigned long pwd_len, Blen, Vlen, XYlen, i;
   unsigned char zero_byte = 0;
   int err, hash_idx;

   LTC_ARGCHK(out != NULL);

   LTC_ARGCHK(password != NULL || password_len == 0);
   LTC_ARGCHK(salt != NULL || salt_len == 0);
   LTC_ARGCHK(N >= 2 && (N & (N - 1)) == 0);   /* must be > 1 and power of 2 */
   LTC_ARGCHK(r >= 1);
   LTC_ARGCHK(p >= 1);
   LTC_ARGCHK(outlen >= 1);
   LTC_ARGCHK(r <= ULONG_MAX / 128 / p);
   LTC_ARGCHK(r <= ULONG_MAX / 256);
   LTC_ARGCHK(N <= ULONG_MAX / 128 / r);

   hash_idx = find_hash("sha256");
   if (hash_idx == -1)                        return CRYPT_INVALID_HASH;

   /* WORKAROUND: HMAC rejects zero-length keys; a single zero byte
    * produces the same zero-padded key block as an empty key. */
   pwd = password;
   pwd_len = password_len;
   if (pwd_len == 0) {
      pwd = &zero_byte;
      pwd_len = 1;
   }

   Blen  = 128 * r * p;
   Vlen  = 128 * r * N;
   XYlen = 256 * r;

   B  = (unsigned char *)XMALLOC(Blen);
   V  = (unsigned char *)XMALLOC(Vlen);
   XY = (unsigned char *)XMALLOC(XYlen);
   if (B == NULL || V == NULL || XY == NULL) {
      err = CRYPT_MEM;
      goto cleanup;
   }

   /* 1: B = PBKDF2-HMAC-SHA256(password, salt, 1, p * 128 * r) */
   {
      unsigned long blen_out = Blen;
      err = pkcs_5_alg2(pwd, pwd_len, salt, salt_len, 1, hash_idx, B, &blen_out);
      if (err != CRYPT_OK) goto cleanup;
   }
   /* 2: for i = 0 to p-1: B[i] = ROMix(r, B[i], N) */
   for (i = 0; i < p; ++i) {
      s_romix(B + i * 128 * r, r, (ulong64)N, V, XY);
   }
   /* 3: DK = PBKDF2-HMAC-SHA256(password, B, 1, dkLen) */
   {
      unsigned long outlen_out = outlen;
      err = pkcs_5_alg2(pwd, pwd_len, B, Blen, 1, hash_idx, out, &outlen_out);
   }

cleanup:
   if (XY != NULL) { zeromem(XY, XYlen); XFREE(XY); }
   if (V  != NULL) { zeromem(V,  Vlen);  XFREE(V);  }
   if (B  != NULL) { zeromem(B,  Blen);  XFREE(B);  }
   return err;
}

#endif /* LTC_SCRYPT */
