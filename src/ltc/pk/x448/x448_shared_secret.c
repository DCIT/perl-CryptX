/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file x448_shared_secret.c
  Create a X448 shared secret
*/

#ifdef LTC_CURVE448

/**
   Create a X448 shared secret.
   @param private_key     The private X448 key in the pair
   @param public_key      The public X448 key in the pair
   @param out             [out] The destination of the shared data
   @param outlen          [in/out] The max size and resulting size of the shared data.
   @return CRYPT_OK if successful
*/
int x448_shared_secret(const    curve448_key *private_key,
                       const    curve448_key *public_key,
                             unsigned char *out, unsigned long *outlen)
{
   LTC_ARGCHK(private_key        != NULL);
   LTC_ARGCHK(public_key         != NULL);
   LTC_ARGCHK(out                != NULL);
   LTC_ARGCHK(outlen             != NULL);

   if (public_key->pka != LTC_PKA_X448) return CRYPT_PK_INVALID_TYPE;
   if (private_key->type != PK_PRIVATE) return CRYPT_PK_INVALID_TYPE;

   if (*outlen < 56uL) {
      *outlen = 56uL;
      return CRYPT_BUFFER_OVERFLOW;
   }

   ec448_scalarmult_internal(out, private_key->priv, public_key->pub);
   *outlen = 56uL;

   return CRYPT_OK;
}

#endif
