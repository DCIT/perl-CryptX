/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 */

/* Implements ECC over Z/pZ for curve y^2 = x^3 + a*x + b
 *
 */

#include "tomcrypt.h"

/* origin of this code - OLPC */

#ifdef LTC_MECC

/**
  Verify a key according to ANSI spec
  @param key     The key to validate
  @return CRYPT_OK if successful
*/

int ecc_verify_key(ecc_key *key)
{
  int err;
  void *prime = NULL;
  void *order = NULL;
  void *a = NULL;
  ecc_point *test_output = NULL;
  test_output = malloc(sizeof(ecc_point));

  if (mp_init_multi(&(test_output->x), &(test_output->y), &(test_output->z), &order, &prime, NULL) != CRYPT_OK) {
    return CRYPT_MEM;
  }

  /* Test 1: Are the x amd y points of the public key in the field? */
  if((err = ltc_mp.read_radix(prime, key->dp->prime, 16)) != CRYPT_OK)                  { goto error;}

  if(ltc_mp.compare_d(key->pubkey.z, 1) == LTC_MP_EQ) {
    if(
       (ltc_mp.compare(key->pubkey.x, prime) != LTC_MP_LT)
       || (ltc_mp.compare(key->pubkey.y, prime) != LTC_MP_LT)
       || (ltc_mp.compare_d(key->pubkey.x, 0) != LTC_MP_GT)
       || (ltc_mp.compare_d(key->pubkey.y, 0) != LTC_MP_GT) )
      {
        err = CRYPT_INVALID_PACKET;
        goto error;
      }
  }

  /* Test 2: is the public key on the curve? */
  if((err = ltc_ecc_is_point(key->dp, key->pubkey.x, key->pubkey.y)) != CRYPT_OK)       { goto error;}

  /* Test 3: does nG = O? (n = order, 0 = point at infinity, G = public key) */
  if((err = ltc_mp.read_radix(order, key->dp->order, 16)) != CRYPT_OK)                  { goto error;}
  if((err = ltc_mp.read_radix(a, key->dp->A, 16)) != CRYPT_OK)                          { goto error;}
  if((err = ltc_ecc_mulmod(order, &(key->pubkey), test_output, a, prime, 1)) != CRYPT_OK) {
    goto error;
  }

  err = CRYPT_OK;
error:
  mp_clear_multi(prime, order, test_output->z, test_output->y, test_output->x, NULL);
  return err;
}

#endif
