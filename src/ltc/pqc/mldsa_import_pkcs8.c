/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file mldsa_import_pkcs8.c
  Import a ML-DSA key in PKCS#8 format
*/

#ifdef LTC_MLDSA

static int s_mldsa_oid_to_alg(enum ltc_oid_id oid_id, int *alg)
{
   LTC_ARGCHK(alg != NULL);

   switch (oid_id) {
      case LTC_OID_MLDSA_44:
         *alg = LTC_MLDSA_44;
         return CRYPT_OK;
      case LTC_OID_MLDSA_65:
         *alg = LTC_MLDSA_65;
         return CRYPT_OK;
      case LTC_OID_MLDSA_87:
         *alg = LTC_MLDSA_87;
         return CRYPT_OK;
      default:
         return CRYPT_PK_INVALID_TYPE;
   }
}

int mldsa_import_pkcs8_asn1(ltc_asn1_list *alg_id, ltc_asn1_list *priv_key,
                            mldsa_key *key)
{
   ltc_asn1_list *decoded = NULL;
   ltc_asn1_list *seed = NULL, *raw_key = NULL;
   ltc_asn1_list seed_custom[1];
   der_flexi_check flexi_should[4];
   enum ltc_oid_id oid_id;
   int alg, err;
   unsigned char *raw_buf = NULL;
   unsigned char seed_buf[32];
   unsigned long inlen, raw_buf_len, key_len, n;
   mldsa_key seed_key;

   LTC_ARGCHK(alg_id   != NULL);
   LTC_ARGCHK(priv_key != NULL);
   LTC_ARGCHK(key      != NULL);
   XMEMSET(&seed_key, 0, sizeof(seed_key));

   if ((err = pk_get_oid_from_asn1(alg_id->child, &oid_id)) != CRYPT_OK) {
      return err;
   }
   if ((err = s_mldsa_oid_to_alg(oid_id, &alg)) != CRYPT_OK) {
      return err;
   }

   if ((err = mldsa_get_sizes(alg, NULL, &key_len, NULL)) != CRYPT_OK) {
      return err;
   }
   if (priv_key->size == key_len) {
      return mldsa_import_raw(priv_key->data, priv_key->size, PK_PRIVATE, alg, key);
   }

   raw_buf = XMALLOC(key_len);
   if (raw_buf == NULL) {
      return CRYPT_MEM;
   }
   raw_buf_len = key_len;
   err = der_decode_octet_string(priv_key->data, priv_key->size, raw_buf, &raw_buf_len);
   if (err == CRYPT_OK) {
      err = (raw_buf_len == key_len)
          ? mldsa_import_raw(raw_buf, raw_buf_len, PK_PRIVATE, alg, key)
          : CRYPT_INVALID_PACKET;
      XFREE(raw_buf);
      return err;
   }
   XFREE(raw_buf);

   LTC_SET_ASN1_CUSTOM_PRIMITIVE(seed_custom, 0, LTC_ASN1_CL_CONTEXT_SPECIFIC, 0,
                                 LTC_ASN1_OCTET_STRING, seed_buf, sizeof(seed_buf));
   err = der_decode_custom_type(priv_key->data, priv_key->size, seed_custom);
   if (err == CRYPT_OK) {
      return mldsa_make_key_from_seed(alg, seed_buf, seed_custom[0].size, key);
   }

   inlen = priv_key->size;
   err = der_decode_sequence_flexi(priv_key->data, &inlen, &decoded);
   if (err != CRYPT_OK) {
      return err;
   }

   n = 0;
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_OCTET_STRING, &seed);
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_OCTET_STRING, &raw_key);
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n, LTC_ASN1_EOL, NULL);
   err = der_flexi_sequence_cmp(decoded, flexi_should);
   if (err != CRYPT_OK && err != CRYPT_INPUT_TOO_LONG) {
      goto cleanup;
   }

   if (seed == NULL || raw_key == NULL) {
      err = CRYPT_INVALID_PACKET;
      goto cleanup;
   }
   if ((err = mldsa_make_key_from_seed(alg, seed->data, seed->size, &seed_key)) != CRYPT_OK) {
      goto cleanup;
   }
   if (seed_key.sklen != raw_key->size ||
       XMEMCMP(seed_key.sk, raw_key->data, raw_key->size) != 0) {
      err = CRYPT_INVALID_PACKET;
      goto cleanup;
   }

   err = mldsa_import_raw(raw_key->data, raw_key->size, PK_PRIVATE, alg, key);

cleanup:
   mldsa_free(&seed_key);
   der_free_sequence_flexi(decoded);
   return err;
}

/**
  Import a ML-DSA private key in PKCS#8 format
  @param in        The packet to import from
  @param inlen     It's length (octets)
  @param pw_ctx    The password context when decrypting the private key
  @param key       [out] Destination for newly imported key
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int mldsa_import_pkcs8(const unsigned char *in, unsigned long inlen, const password_ctx  *pw_ctx, mldsa_key *key)
{
   int alg, err;
   ltc_asn1_list *l = NULL;
   ltc_asn1_list *alg_id, *priv_key;
   enum ltc_oid_id oid_id;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   err = pkcs8_decode_flexi(in, inlen, pw_ctx, &l);
   if (err != CRYPT_OK) {
      return err;
   }

   if ((err = pkcs8_get_children(l, &oid_id, &alg_id, &priv_key)) != CRYPT_OK) {
      goto cleanup;
   }
   err = s_mldsa_oid_to_alg(oid_id, &alg);
   if (err != CRYPT_OK) {
      err = CRYPT_INVALID_PACKET;
      goto cleanup;
   }
   LTC_UNUSED_PARAM(alg);

   err = mldsa_import_pkcs8_asn1(alg_id, priv_key, key);

cleanup:
   der_free_sequence_flexi(l);
   return err;
}

#endif
