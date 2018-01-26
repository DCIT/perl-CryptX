/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_MECC

int ecc_set_dp(const ltc_ecc_set_type *set, ecc_key *key)
{
   unsigned long i;
   int err;

   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(set != NULL);

   if ((err = mp_init_multi(&key->dp.prime, &key->dp.order, &key->dp.A, &key->dp.B,
                            &key->dp.base.x, &key->dp.base.y, &key->dp.base.z,
                            &key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                            NULL)) != CRYPT_OK) {
      return err;
   }

   /* A, B, order, prime, Gx, Gy */
   if ((err = mp_read_radix(key->dp.prime, set->prime, 16)) != CRYPT_OK) { goto error; }
   if ((err = mp_read_radix(key->dp.order, set->order, 16)) != CRYPT_OK) { goto error; }
   if ((err = mp_read_radix(key->dp.A, set->A, 16)) != CRYPT_OK)         { goto error; }
   if ((err = mp_read_radix(key->dp.B, set->B, 16)) != CRYPT_OK)         { goto error; }
   if ((err = mp_read_radix(key->dp.base.x, set->Gx, 16)) != CRYPT_OK)   { goto error; }
   if ((err = mp_read_radix(key->dp.base.y, set->Gy, 16)) != CRYPT_OK)   { goto error; }
   if ((err = mp_set(key->dp.base.z, 1)) != CRYPT_OK)                    { goto error; }
   /* cofactor & size */
   key->dp.cofactor = set->cofactor;
   key->dp.size = mp_unsigned_bin_size(key->dp.prime);
   /* OID */
   key->dp.oidlen = set->oidlen;
   for (i = 0; i < key->dp.oidlen; i++) key->dp.oid[i] = set->oid[i];
   /* success */
   return CRYPT_OK;

error:
   ecc_free(key);
   return err;
}

int ecc_set_dp_size(int size, ecc_key *key)
{
   const ltc_ecc_set_type *dp = NULL;
   int err;

   /* for compatibility with libtomcrypt-1.17 the sizes below must match the specific curves */
   if (size <= 14) {
      if ((err = ecc_get_set_by_name("SECP112R1", &dp)) != CRYPT_OK) return err;
      return ecc_set_dp(dp, key);
   }
   else if (size <= 16) {
      if ((err = ecc_get_set_by_name("SECP128R1", &dp)) != CRYPT_OK) return err;
      return ecc_set_dp(dp, key);
   }
   else if (size <= 20) {
      if ((err = ecc_get_set_by_name("SECP160R1", &dp)) != CRYPT_OK) return err;
      return ecc_set_dp(dp, key);
   }
   else if (size <= 24) {
      if ((err = ecc_get_set_by_name("SECP192R1", &dp)) != CRYPT_OK) return err;
      return ecc_set_dp(dp, key);
   }
   else if (size <= 28) {
      if ((err = ecc_get_set_by_name("SECP224R1", &dp)) != CRYPT_OK) return err;
      return ecc_set_dp(dp, key);
   }
   else if (size <= 32) {
      if ((err = ecc_get_set_by_name("SECP256R1", &dp)) != CRYPT_OK) return err;
      return ecc_set_dp(dp, key);
   }
   else if (size <= 48) {
      if ((err = ecc_get_set_by_name("SECP384R1", &dp)) != CRYPT_OK) return err;
      return ecc_set_dp(dp, key);
   }
   else if (size <= 66) {
      if ((err = ecc_get_set_by_name("SECP521R1", &dp)) != CRYPT_OK) return err;
      return ecc_set_dp(dp, key);
   }

   return CRYPT_INVALID_ARG;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
