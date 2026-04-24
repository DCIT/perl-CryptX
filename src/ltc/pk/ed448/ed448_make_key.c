/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ed448_make_key.c
  Create an Ed448 key, Steffen Jaeckel
*/

#ifdef LTC_CURVE448

/**
   Create an Ed448 key
   @param prng     An active PRNG state
   @param wprng    The index of the PRNG desired
   @param key      [out] Destination of a newly created private key pair
   @return CRYPT_OK if successful
*/
int ed448_make_key(prng_state *prng, int wprng, curve448_key *key)
{
   int err;

   LTC_ARGCHK(prng != NULL);
   LTC_ARGCHK(key  != NULL);

   if ((err = ec448_keypair_internal(prng, wprng, key->pub, key->priv)) != CRYPT_OK) {
      return err;
   }

   key->type = PK_PRIVATE;
   key->pka = LTC_PKA_ED448;

   return err;
}

#endif
