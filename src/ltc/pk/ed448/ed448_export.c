/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ed448_export.c
  Export an Ed448 key to a binary packet, Steffen Jaeckel
*/

#ifdef LTC_CURVE448

/**
   Export an Ed448 key to a binary packet
   @param out    [out] The destination for the key
   @param outlen [in/out] The max size and resulting size of the Ed448 key
   @param which  Which type of key (PK_PRIVATE, PK_PUBLIC|PK_STD or PK_PUBLIC)
   @param key    The key you wish to export
   @return CRYPT_OK if successful
*/
int ed448_export(       unsigned char *out, unsigned long *outlen,
                                  int  which,
                 const curve448_key *key)
{
   LTC_ARGCHK(key != NULL);

   if (key->pka != LTC_PKA_ED448) return CRYPT_PK_INVALID_TYPE;

   return ec448_export(out, outlen, which, key);
}

#endif
