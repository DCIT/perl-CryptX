/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ed448_import_pkcs8.c
  Import an Ed448 key in PKCS#8 format, Steffen Jaeckel
*/

#ifdef LTC_CURVE448

int ed448_import_pkcs8_asn1(ltc_asn1_list  *alg_id, ltc_asn1_list *priv_key,
                            curve448_key *key)
{
   return ec448_import_pkcs8_asn1(alg_id, priv_key, LTC_OID_ED448, key);
}

/**
  Import an Ed448 private key in PKCS#8 format
  @param in        The packet to import from
  @param inlen     It's length (octets)
  @param pw_ctx    The password context when decrypting the private key
  @param key       [out] Destination for newly imported key
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int ed448_import_pkcs8(const unsigned char  *in, unsigned long inlen,
                       const password_ctx   *pw_ctx,
                             curve448_key *key)
{
   return ec448_import_pkcs8(in, inlen, pw_ctx, LTC_OID_ED448, key);
}

#endif
