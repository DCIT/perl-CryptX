/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_KMAC

/**
   KMAC multiple blocks of memory to produce the authentication tag

   @param variant  128 or 256 (optionally OR-ed with LTC_KMAC_XOF)
   @param key      The secret key
   @param keylen   The length of the secret key (octets)
   @param cust     Optional customization string (may be NULL when custlen == 0)
   @param custlen  Length of the customization string (octets)
   @param out      [out] Destination of the MAC
   @param outlen   [in/out] Requested length on entry, produced length on return
   @param in       The data to authenticate
   @param inlen    The length of the data (octets)
   @param ...      tuples of (data, len) pairs to authenticate, terminated with (NULL, x)
   @return CRYPT_OK if successful
*/
int kmac_memory_multi(int variant,
                      const unsigned char *key,  unsigned long keylen,
                      const unsigned char *cust, unsigned long custlen,
                            unsigned char *out,  unsigned long *outlen,
                      const unsigned char *in,   unsigned long inlen, ...)
{
   kmac_state st;
   int err;
   va_list args;
   const unsigned char *curptr;
   unsigned long curlen;

   LTC_ARGCHK(key    != NULL || keylen  == 0);
   LTC_ARGCHK(cust   != NULL || custlen == 0);
   LTC_ARGCHK(in     != NULL || inlen   == 0);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   va_start(args, inlen);
   curptr = in;
   curlen = inlen;
   if ((err = kmac_init(&st, variant, key, keylen, cust, custlen)) != CRYPT_OK) goto LBL_ERR;
   for (;;) {
      if ((err = kmac_process(&st, curptr, curlen)) != CRYPT_OK) goto LBL_ERR;
      curptr = va_arg(args, const unsigned char*);
      if (curptr == NULL) break;
      curlen = va_arg(args, unsigned long);
   }
   err = kmac_done(&st, out, outlen);
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(&st, sizeof(st));
#endif
   va_end(args);
   return err;
}

#endif
