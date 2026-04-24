/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ec448_export.c
  Generic export of a Curve448 key to a binary packet
*/

#ifdef LTC_CURVE448

/**
   Generic export of a Curve448 key to a binary packet
   @param out    [out] The destination for the key
   @param outlen [in/out] The max size and resulting size of the key
   @param which  Which type of key (PK_PRIVATE, PK_PUBLIC|PK_STD or PK_PUBLIC)
   @param key    The key you wish to export
   @return CRYPT_OK if successful
*/
int ec448_export(       unsigned char *out, unsigned long *outlen,
                                  int  which,
                 const curve448_key *key)
{
   int err, std;
   const char* OID;
   unsigned long oid[16], oidlen;
   ltc_asn1_list alg_id[1];
   enum ltc_oid_id oid_id;
   unsigned char private_key[59];
   unsigned long version, private_key_len = sizeof(private_key);
   unsigned long key_sz;

   LTC_ARGCHK(out       != NULL);
   LTC_ARGCHK(outlen    != NULL);
   LTC_ARGCHK(key       != NULL);

   std = which & PK_STD;
   which &= ~PK_STD;
   if ((err = pk_get_oid_id(key->pka, &oid_id)) != CRYPT_OK) {
      return err;
   }

   /* X448 keys are 56 bytes, Ed448 keys are 57 bytes */
   key_sz = (key->pka == LTC_PKA_ED448) ? 57uL : 56uL;

   if (which == PK_PRIVATE) {
      if(key->type != PK_PRIVATE) return CRYPT_PK_INVALID_TYPE;

      if (std == PK_STD) {
         if ((err = pk_get_oid(oid_id, &OID)) != CRYPT_OK) {
            return err;
         }
         oidlen = LTC_ARRAY_SIZE(oid);
         if ((err = pk_oid_str_to_num(OID, oid, &oidlen)) != CRYPT_OK) {
            return err;
         }

         LTC_SET_ASN1(alg_id, 0, LTC_ASN1_OBJECT_IDENTIFIER, oid, oidlen);

         /* encode private key as PKCS#8 */
         if ((err = der_encode_octet_string(key->priv, key_sz, private_key, &private_key_len)) != CRYPT_OK) {
            return err;
         }

         version = 0;
         err = der_encode_sequence_multi(out, outlen,
                                   LTC_ASN1_SHORT_INTEGER,            1uL, &version,
                                   LTC_ASN1_SEQUENCE,                 1uL, alg_id,
                                   LTC_ASN1_OCTET_STRING, private_key_len, private_key,
                                   LTC_ASN1_EOL,                      0uL, NULL);
      } else {
         if (*outlen < key_sz) {
            err = CRYPT_BUFFER_OVERFLOW;
         } else {
            XMEMCPY(out, key->priv, key_sz);
            err = CRYPT_OK;
         }
         *outlen = key_sz;
      }
   } else {
      if (std == PK_STD) {
         /* encode public key as SubjectPublicKeyInfo */
         err = x509_encode_subject_public_key_info(out, outlen, oid_id, key->pub, key_sz, LTC_ASN1_EOL, NULL, 0);
      } else {
         if (*outlen < key_sz) {
            err = CRYPT_BUFFER_OVERFLOW;
         } else {
            XMEMCPY(out, key->pub, key_sz);
            err = CRYPT_OK;
         }
         *outlen = key_sz;
      }
   }

   return err;
}

#endif
