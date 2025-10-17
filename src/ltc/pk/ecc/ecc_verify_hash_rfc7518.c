/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

/**
  @file ecc_verify_hash_rfc7518.c
  ECC Crypto, Tom St Denis
*/

int ecc_verify_hash_rfc7518_internal(const unsigned char *sig,  unsigned long siglen,
                            const unsigned char *hash, unsigned long hashlen,
                            int *stat, const ecc_key *key)
{
   void *r, *s;
   int err;
   unsigned long i;

   LTC_ARGCHK(sig != NULL);
   LTC_ARGCHK(key != NULL);

   if ((err = ltc_mp_init_multi(&r, &s, LTC_NULL)) != CRYPT_OK) return err;

   /* RFC7518 format - raw (r,s) */
   i = ltc_mp_unsigned_bin_size(key->dp.order);
   if (siglen != (2 * i)) {
      err = CRYPT_INVALID_PACKET;
      goto error;
   }
   if ((err = ltc_mp_read_unsigned_bin(r, (unsigned char *)sig, i)) != CRYPT_OK) goto error;
   if ((err = ltc_mp_read_unsigned_bin(s, (unsigned char *)sig + i, i)) != CRYPT_OK) goto error;

   err = ecc_verify_hash_internal(r, s, hash, hashlen, stat, key);

error:
   ltc_mp_deinit_multi(r, s, LTC_NULL);
   return err;
}

#endif
