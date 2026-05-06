/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_KMAC

/**
   KMAC a block of memory to produce the authentication tag

   @param variant  128 or 256 (optionally OR-ed with LTC_KMAC_XOF)
   @param key      The secret key
   @param keylen   The length of the secret key (octets)
   @param cust     Optional customization string (may be NULL when custlen == 0)
   @param custlen  Length of the customization string (octets)
   @param in       The data to authenticate
   @param inlen    The length of the data (octets)
   @param out      [out] Destination of the MAC
   @param outlen   [in/out] Requested length on entry, produced length on return
   @return CRYPT_OK if successful
*/
int kmac_memory(int variant,
                const unsigned char *key,  unsigned long keylen,
                const unsigned char *cust, unsigned long custlen,
                const unsigned char *in,   unsigned long inlen,
                      unsigned char *out,  unsigned long *outlen)
{
   kmac_state st;
   int err;

   LTC_ARGCHK(key    != NULL || keylen  == 0);
   LTC_ARGCHK(cust   != NULL || custlen == 0);
   LTC_ARGCHK(in     != NULL || inlen   == 0);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   if ((err = kmac_init(&st, variant, key, keylen, cust, custlen)) != CRYPT_OK) goto LBL_ERR;
   if ((err = kmac_process(&st, in, inlen))                        != CRYPT_OK) goto LBL_ERR;
   err = kmac_done(&st, out, outlen);
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(&st, sizeof(st));
#endif
   return err;
}

#endif
