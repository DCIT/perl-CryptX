/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

#if defined(LTC_MDSA) || defined(LTC_MECC)
/**
  Generate a random number N with given bitlength (note: MSB can be 0)
*/

int rand_bn_bits(void *N, int bits, prng_state *prng, int wprng)
{
   int res, bytes;
   unsigned char *buf, mask;

   LTC_ARGCHK(N != NULL);
   LTC_ARGCHK(bits > 1);

   /* check PRNG */
   if ((res = prng_is_valid(wprng)) != CRYPT_OK) return res;

   bytes = (bits+7) >> 3;
   mask = 0xff >> (bits % 8 == 0 ? 0 : 8 - bits % 8);

   /* allocate buffer */
   if ((buf = XCALLOC(1, bytes)) == NULL) return CRYPT_MEM;

   /* generate random bytes */
   if (prng_descriptor[wprng].read(buf, bytes, prng) != (unsigned long)bytes) {
      res = CRYPT_ERROR_READPRNG;
      goto cleanup;
   }
   /* mask bits */
   buf[0] &= mask;
   /* load value */
   if ((res = ltc_mp_read_unsigned_bin(N, buf, bytes)) != CRYPT_OK) goto cleanup;

   res = CRYPT_OK;

cleanup:
#ifdef LTC_CLEAN_STACK
   zeromem(buf, bytes);
#endif
   XFREE(buf);
   return res;
}

/**
  Generate a random number N in a range: 1 <= N < limit
*/
int rand_bn_upto(void *N, void *limit, prng_state *prng, int wprng)
{
   int res, bits;

   LTC_ARGCHK(N != NULL);
   LTC_ARGCHK(limit != NULL);

   bits = ltc_mp_count_bits(limit);
   do {
     res = rand_bn_bits(N, bits, prng, wprng);
     if (res != CRYPT_OK) return res;
   } while (ltc_mp_cmp_d(N, 0) != LTC_MP_GT || ltc_mp_cmp(N, limit) != LTC_MP_LT);

   return CRYPT_OK;
}
#endif
