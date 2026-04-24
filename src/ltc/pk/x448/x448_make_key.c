/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file x448_make_key.c
  Create a X448 key
*/

#ifdef LTC_CURVE448

/**
   Create a X448 key
   @param prng     An active PRNG state
   @param wprng    The index of the PRNG desired
   @param key      [out] Destination of a newly created private key pair
   @return CRYPT_OK if successful
*/
int x448_make_key(prng_state *prng, int wprng, curve448_key *key)
{
   int err;

   LTC_ARGCHK(prng != NULL);
   LTC_ARGCHK(key  != NULL);

   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   if (prng_descriptor[wprng].read(key->priv, 56uL, prng) != 56uL) {
      return CRYPT_ERROR_READPRNG;
   }

   ec448_scalarmult_base_internal(key->pub, key->priv);

   key->type = PK_PRIVATE;
   key->pka = LTC_PKA_X448;

   return err;
}

#endif
