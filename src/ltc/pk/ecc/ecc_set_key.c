/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

int ecc_set_key(const unsigned char *in, unsigned long inlen, int type, ecc_key *key)
{
   int err;
   void *prime, *a, *b;

   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(in != NULL);
   LTC_ARGCHK(inlen > 0);

   prime = key->dp.prime;
   a     = key->dp.A;
   b     = key->dp.B;

   if (type == PK_PRIVATE) {
      /* load private key */
      if ((err = ltc_mp_read_unsigned_bin(key->k, in, inlen)) != CRYPT_OK) {
         goto error;
      }
      if (ltc_mp_iszero(key->k) || (ltc_mp_cmp(key->k, key->dp.order) != LTC_MP_LT)) {
         err = CRYPT_INVALID_PACKET;
         goto error;
      }
      /* compute public key */
      if ((err = ltc_mp.ecc_ptmul(key->k, &key->dp.base, &key->pubkey, a, prime, 1)) != CRYPT_OK)         { goto error; }
   }
   else if (type == PK_PUBLIC) {
      /* load public key */
      if ((err = ltc_ecc_import_point(in, inlen, prime, a, b, key->pubkey.x, key->pubkey.y)) != CRYPT_OK) { goto error; }
      if ((err = ltc_mp_set(key->pubkey.z, 1)) != CRYPT_OK)                                                   { goto error; }
   }
   else {
      err = CRYPT_INVALID_PACKET;
      goto error;
   }

   /* point on the curve + other checks */
   if ((err = ltc_ecc_verify_key(key)) != CRYPT_OK) {
      goto error;
   }

   key->type = type;
   return CRYPT_OK;

error:
   ecc_free(key);
   return err;
}

#endif
