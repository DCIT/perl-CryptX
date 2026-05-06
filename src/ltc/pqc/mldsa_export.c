/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file mldsa_export.c
  Export a ML-DSA key to a binary packet
*/

#ifdef LTC_MLDSA

static int s_mldsa_alg_to_oid(int alg, enum ltc_oid_id *oid_id)
{
   LTC_ARGCHK(oid_id != NULL);

   switch (alg) {
      case LTC_MLDSA_44:
         *oid_id = LTC_OID_MLDSA_44;
         return CRYPT_OK;
      case LTC_MLDSA_65:
         *oid_id = LTC_OID_MLDSA_65;
         return CRYPT_OK;
      case LTC_MLDSA_87:
         *oid_id = LTC_OID_MLDSA_87;
         return CRYPT_OK;
      default:
         return CRYPT_PK_INVALID_TYPE;
   }
}

/**
   Export a ML-DSA key to a binary packet
   @param out    [out] The destination for the key
   @param outlen [in/out] The max size and resulting size of the ML-DSA key
   @param which  Which type of key (PK_PRIVATE, PK_PUBLIC|PK_STD or PK_PUBLIC)
   @param key    The key you wish to export
   @return CRYPT_OK if successful
*/
int mldsa_export(unsigned char *out, unsigned long *outlen,
                 int which, const mldsa_key *key)
{
   int err, std;
   enum ltc_oid_id oid_id;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   std = which & PK_STD;
   which &= ~PK_STD;

   if ((err = s_mldsa_alg_to_oid(key->alg, &oid_id)) != CRYPT_OK) {
      return err;
   }

   if (which == PK_PRIVATE) {
      const char *OID;
      unsigned long version, oid[16], oidlen;
      unsigned char *private_key;
      unsigned long private_key_len;
      ltc_asn1_list alg_id[1];

      if (key->type != PK_PRIVATE || key->sk == NULL) return CRYPT_PK_INVALID_TYPE;

      if (std != PK_STD) {
         return mldsa_export_raw(out, outlen, which, key);
      }

      if ((err = pk_get_oid(oid_id, &OID)) != CRYPT_OK) {
         return err;
      }
      oidlen = LTC_ARRAY_SIZE(oid);
      if ((err = pk_oid_str_to_num(OID, oid, &oidlen)) != CRYPT_OK) {
         return err;
      }
      LTC_SET_ASN1(alg_id, 0, LTC_ASN1_OBJECT_IDENTIFIER, oid, oidlen);

      if ((err = der_length_octet_string(key->sklen, &private_key_len)) != CRYPT_OK) {
         return err;
      }
      private_key = XMALLOC(private_key_len);
      if (private_key == NULL) {
         return CRYPT_MEM;
      }

      err = der_encode_octet_string(key->sk, key->sklen, private_key, &private_key_len);
      if (err == CRYPT_OK) {
         version = 0;
         err = der_encode_sequence_multi(out, outlen,
                                         LTC_ASN1_SHORT_INTEGER, 1uL, &version,
                                         LTC_ASN1_SEQUENCE,      1uL, alg_id,
                                         LTC_ASN1_OCTET_STRING, private_key_len, private_key,
                                         LTC_ASN1_EOL,           0uL, NULL);
      }

      XFREE(private_key);
      return err;
   }

   if (which != PK_PUBLIC) {
      return CRYPT_INVALID_ARG;
   }
   if (key->pk == NULL) return CRYPT_PK_INVALID_TYPE;

   if (std == PK_STD) {
      return x509_encode_subject_public_key_info(out, outlen, oid_id,
                                                 key->pk, key->pklen,
                                                 LTC_ASN1_EOL, NULL, 0uL);
   }

   return mldsa_export_raw(out, outlen, which, key);
}

#endif
