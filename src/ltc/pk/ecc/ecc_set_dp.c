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

int ecc_set_dp(const ltc_ecc_curve *curve, ecc_key *key)
{
   unsigned long i;
   int err;

   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(curve != NULL);

   if ((err = mp_init_multi(&key->dp.prime, &key->dp.order, &key->dp.A, &key->dp.B,
                            &key->dp.base.x, &key->dp.base.y, &key->dp.base.z,
                            &key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                            NULL)) != CRYPT_OK) {
      return err;
   }

   /* A, B, order, prime, Gx, Gy */
   if ((err = mp_read_radix(key->dp.prime, curve->prime, 16)) != CRYPT_OK) { goto error; }
   if ((err = mp_read_radix(key->dp.order, curve->order, 16)) != CRYPT_OK) { goto error; }
   if ((err = mp_read_radix(key->dp.A, curve->A, 16)) != CRYPT_OK)         { goto error; }
   if ((err = mp_read_radix(key->dp.B, curve->B, 16)) != CRYPT_OK)         { goto error; }
   if ((err = mp_read_radix(key->dp.base.x, curve->Gx, 16)) != CRYPT_OK)   { goto error; }
   if ((err = mp_read_radix(key->dp.base.y, curve->Gy, 16)) != CRYPT_OK)   { goto error; }
   if ((err = mp_set(key->dp.base.z, 1)) != CRYPT_OK)                      { goto error; }
   /* cofactor & size */
   key->dp.cofactor = curve->cofactor;
   key->dp.size = mp_unsigned_bin_size(key->dp.prime);
   /* OID */
   key->dp.oidlen = curve->oidlen;
   for (i = 0; i < key->dp.oidlen; i++) key->dp.oid[i] = curve->oid[i];
   /* success */
   return CRYPT_OK;

error:
   ecc_free(key);
   return err;
}

int ecc_set_dp_by_size(int size, ecc_key *key)
{
   const ltc_ecc_curve *cu = NULL;
   int err = CRYPT_ERROR;

   /* for compatibility with libtomcrypt-1.17 the sizes below must match the specific curves */
   if (size <= 14) {
      err = ecc_get_curve_by_name("SECP112R1", &cu);
   }
   else if (size <= 16) {
      err = ecc_get_curve_by_name("SECP128R1", &cu);
   }
   else if (size <= 20) {
      err = ecc_get_curve_by_name("SECP160R1", &cu);
   }
   else if (size <= 24) {
      err = ecc_get_curve_by_name("SECP192R1", &cu);
   }
   else if (size <= 28) {
      err = ecc_get_curve_by_name("SECP224R1", &cu);
   }
   else if (size <= 32) {
      err = ecc_get_curve_by_name("SECP256R1", &cu);
   }
   else if (size <= 48) {
      err = ecc_get_curve_by_name("SECP384R1", &cu);
   }
   else if (size <= 66) {
      err = ecc_get_curve_by_name("SECP521R1", &cu);
   }

   if (err == CRYPT_OK && cu != NULL) return ecc_set_dp(cu, key);

   return CRYPT_INVALID_ARG;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
