/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file x448_import_x509.c
  Import a X448 key from a X.509 certificate
*/

#ifdef LTC_CURVE448

static int s_x448_decode(const unsigned char *in, unsigned long inlen, curve448_key *key)
{
   if (inlen != 56uL) return CRYPT_PK_INVALID_SIZE;
   XMEMCPY(key->pub, in, 56uL);
   return CRYPT_OK;
}

/**
  Import a X448 public key from a X.509 certificate
  @param in     The DER encoded X.509 certificate
  @param inlen  The length of the certificate
  @param key    [out] Where to import the key to
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int x448_import_x509(const unsigned char *in, unsigned long inlen, curve448_key *key)
{
   int err;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   if ((err = x509_decode_public_key_from_certificate(in, inlen,
                                                      LTC_OID_X448,
                                                      LTC_ASN1_EOL, NULL, NULL,
                                                      (public_key_decode_cb)s_x448_decode, key)) != CRYPT_OK) {
      return err;
   }
   key->type = PK_PUBLIC;
   key->pka = LTC_PKA_X448;

   return err;
}

#endif
