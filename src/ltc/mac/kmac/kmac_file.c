/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_KMAC

/**
   KMAC a file

   @param variant  128 or 256 (optionally OR-ed with LTC_KMAC_XOF)
   @param key      The secret key
   @param keylen   The length of the secret key (octets)
   @param cust     Optional customization string (may be NULL when custlen == 0)
   @param custlen  Length of the customization string (octets)
   @param fname    The name of the file you wish to MAC
   @param out      [out] Destination of the MAC
   @param outlen   [in/out] Requested length on entry, produced length on return
   @return CRYPT_OK if successful, CRYPT_NOP if file support has been disabled
*/
int kmac_file(int variant,
              const unsigned char *key,  unsigned long keylen,
              const unsigned char *cust, unsigned long custlen,
                       const char *fname,
                    unsigned char *out,  unsigned long *outlen)
{
#ifdef LTC_NO_FILE
   LTC_UNUSED_PARAM(variant);
   LTC_UNUSED_PARAM(key);
   LTC_UNUSED_PARAM(keylen);
   LTC_UNUSED_PARAM(cust);
   LTC_UNUSED_PARAM(custlen);
   LTC_UNUSED_PARAM(fname);
   LTC_UNUSED_PARAM(out);
   LTC_UNUSED_PARAM(outlen);
   return CRYPT_NOP;
#else
   kmac_state st;
   FILE *in;
   unsigned char *buf;
   size_t x;
   int err;

   LTC_ARGCHK(fname  != NULL);
   LTC_ARGCHK(key    != NULL || keylen  == 0);
   LTC_ARGCHK(cust   != NULL || custlen == 0);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   if ((buf = XMALLOC(LTC_FILE_READ_BUFSIZE)) == NULL) {
      return CRYPT_MEM;
   }

   if ((err = kmac_init(&st, variant, key, keylen, cust, custlen)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   in = fopen(fname, "rb");
   if (in == NULL) {
      err = CRYPT_FILE_NOTFOUND;
      goto LBL_ERR;
   }

   do {
      x = fread(buf, 1, LTC_FILE_READ_BUFSIZE, in);
      if ((err = kmac_process(&st, buf, (unsigned long)x)) != CRYPT_OK) {
         fclose(in);
         goto LBL_CLEANBUF;
      }
   } while (x == LTC_FILE_READ_BUFSIZE);

   if (fclose(in) != 0) {
      err = CRYPT_ERROR;
      goto LBL_CLEANBUF;
   }

   err = kmac_done(&st, out, outlen);

LBL_CLEANBUF:
   zeromem(buf, LTC_FILE_READ_BUFSIZE);
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(&st, sizeof(st));
#endif
   XFREE(buf);
   return err;
#endif
}

#endif
