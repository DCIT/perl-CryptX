/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ec448_crypto_ctx.c
  Build DOM4 context prefix for Ed448ctx / Ed448ph (RFC 8032, Section 5.2).
  DOM4(x, y) = "SigEd448" || octet(x) || octet(OLEN(y)) || y
*/

#ifdef LTC_CURVE448

/**
   @param out     [out] Destination buffer
   @param outlen  [in/out] Max size / resulting size
   @param flag    0 for Ed448/Ed448ctx, 1 for Ed448ph
   @param ctx     Context string (may be NULL if ctxlen==0)
   @param ctxlen  Length of context (0..255)
   @return CRYPT_OK if successful
*/
int ec448_crypto_ctx(unsigned char *out, unsigned long *outlen, unsigned char flag,
                     const unsigned char *ctx, unsigned long ctxlen)
{
   unsigned char *buf = out;

   const char *prefix = "SigEd448";
   const unsigned long prefix_len = 8;
   const unsigned char ctxlen8 = (unsigned char)ctxlen;

   if (ctxlen > 255u) return CRYPT_INPUT_TOO_LONG;
   if (*outlen < prefix_len + 2u + ctxlen) return CRYPT_BUFFER_OVERFLOW;

   XMEMCPY(buf, prefix, prefix_len);
   buf += prefix_len;
   XMEMCPY(buf, &flag, 1);
   buf++;
   XMEMCPY(buf, &ctxlen8, 1);
   buf++;

   if (ctxlen > 0u) {
      LTC_ARGCHK(ctx != NULL);
      XMEMCPY(buf, ctx, ctxlen);
      buf += ctxlen;
   }

   *outlen = (unsigned long)(buf - out);

   return CRYPT_OK;
}

#endif
