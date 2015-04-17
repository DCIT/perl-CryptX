/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

/* Implements ECC over Z/pZ for curve y^2 = x^3 + a*x + b
 *
 */

#include "tomcrypt.h"

#ifdef LTC_MECC

static int _populate_dp_from_oid(unsigned long *oid, unsigned long size, ltc_ecc_set_type *dp)
{
  int i;
  unsigned long len;

  for(i=0; ltc_ecc_sets[i].size != 0; i++) {
    if ((size == ltc_ecc_sets[i].oid.OIDlen) &&
        (XMEM_NEQ(oid, ltc_ecc_sets[i].oid.OID, sizeof(unsigned long) * ltc_ecc_sets[i].oid.OIDlen) == 0)) {
      break;
    }
  }
  if (ltc_ecc_sets[i].size == 0) return CRYPT_INVALID_ARG; /* not found */

  /* a */
  len = (unsigned long)strlen(ltc_ecc_sets[i].A);
  if ((dp->A = XMALLOC(1+len)) == NULL)         goto cleanup1;
  strncpy(dp->A, ltc_ecc_sets[i].A, 1+len);
  /* b */
  len = (unsigned long)strlen(ltc_ecc_sets[i].B);
  if ((dp->B = XMALLOC(1+len)) == NULL)         goto cleanup2;
  strncpy(dp->B, ltc_ecc_sets[i].B, 1+len);
  /* order */
  len = (unsigned long)strlen(ltc_ecc_sets[i].order);
  if ((dp->order = XMALLOC(1+len)) == NULL)     goto cleanup3;
  strncpy(dp->order, ltc_ecc_sets[i].order, 1+len);
  /* prime */
  len = (unsigned long)strlen(ltc_ecc_sets[i].prime);
  if ((dp->prime = XMALLOC(1+len)) == NULL)     goto cleanup4;
  strncpy(dp->prime, ltc_ecc_sets[i].prime, 1+len);
  /* gx */
  len = (unsigned long)strlen(ltc_ecc_sets[i].Gx);
  if ((dp->Gx = XMALLOC(1+len)) == NULL)        goto cleanup5;
  strncpy(dp->Gx, ltc_ecc_sets[i].Gx, 1+len);
  /* gy */
  len = (unsigned long)strlen(ltc_ecc_sets[i].Gy);
  if ((dp->Gy = XMALLOC(1+len)) == NULL)        goto cleanup6;
  strncpy(dp->Gy, ltc_ecc_sets[i].Gy, 1+len);
  /* cofactor & size */
  dp->cofactor = ltc_ecc_sets[i].cofactor;
  dp->size = ltc_ecc_sets[i].size;
  /* name */
  len = (unsigned long)strlen(ltc_ecc_sets[i].name);
  if ((dp->name = XMALLOC(1+len)) == NULL)      goto cleanup6;
  strncpy(dp->name, ltc_ecc_sets[i].name, 1+len);
  /* done - success */
  return CRYPT_OK;

cleanup7:
  XFREE(dp->Gy);
cleanup6:
  XFREE(dp->Gx);
cleanup5:
  XFREE(dp->prime);
cleanup4:
  XFREE(dp->order);
cleanup3:
  XFREE(dp->B);
cleanup2:
  XFREE(dp->A);
cleanup1:
  return CRYPT_MEM;
}

static int _populate_dp(void *a, void *b, void *prime, void *order, void *gx, void *gy, unsigned long cofactor, ltc_ecc_set_type *dp)
{
  unsigned char buf[ECC_BUF_SIZE];
  unsigned long len;

  /* a */
  mp_tohex(a, (char *)buf);
  len = (unsigned long)strlen((char *)buf);
  if ((dp->A = XMALLOC(1+len)) == NULL)         goto cleanup1;
  strncpy(dp->A, (char*)buf, 1+len);
  /* b */
  mp_tohex(b, (char *)buf);
  len = (unsigned long)strlen((char *)buf);
  if ((dp->B = XMALLOC(1+len)) == NULL)         goto cleanup2;
  strncpy(dp->B, (char*)buf, 1+len);
  /* order */
  mp_tohex(order, (char *)buf);
  len = (unsigned long)strlen((char *)buf);
  if ((dp->order = XMALLOC(1+len)) == NULL)     goto cleanup3;
  strncpy(dp->order, (char*)buf, 1+len);
  /* prime */
  mp_tohex(prime, (char *)buf);
  len = (unsigned long)strlen((char *)buf);
  if ((dp->prime = XMALLOC(1+len)) == NULL)     goto cleanup4;
  strncpy(dp->prime, (char*)buf, 1+len);
  /* gx */
  mp_tohex(gx, (char *)buf);
  len = (unsigned long)strlen((char *)buf);
  if ((dp->Gx = XMALLOC(1+len)) == NULL)        goto cleanup5;
  strncpy(dp->Gx, (char*)buf, 1+len);
  /* gy */
  mp_tohex(gy, (char *)buf);
  len = (unsigned long)strlen((char *)buf);
  if ((dp->Gy = XMALLOC(1+len)) == NULL)        goto cleanup6;
  strncpy(dp->Gy, (char*)buf, 1+len);
  /* cofactor & size */
  dp->cofactor = cofactor;
  dp->size = mp_unsigned_bin_size(prime);
  /* name */
  if ((dp->name = XMALLOC(7)) == NULL)          goto cleanup7;
  strcpy(dp->name, "custom");  /* XXX-TODO check this */
  /* done - success */
  return CRYPT_OK;

  /* XFREE(dp->name); **** warning: statement not reached *** */
cleanup7:
  XFREE(dp->Gy);
cleanup6:
  XFREE(dp->Gx);
cleanup5:
  XFREE(dp->prime);
cleanup4:
  XFREE(dp->order);
cleanup3:
  XFREE(dp->B);
cleanup2:
  XFREE(dp->A);
cleanup1:
  return CRYPT_MEM;
}

int ecc_import_full(const unsigned char *in, unsigned long inlen, ecc_key *key, ltc_ecc_set_type *dp)
{
  void *prime, *order, *a, *b, *gx, *gy;
  ltc_asn1_list seq_fieldid[2], seq_curve[3], seq_ecparams[6], seq_priv[4], seq_pub[2];
  unsigned char bin_a[ECC_MAXSIZE], bin_b[ECC_MAXSIZE], bin_k[ECC_MAXSIZE], bin_g[2*ECC_MAXSIZE+1], bin_xy[2*ECC_MAXSIZE+2], bin_seed[128];
  unsigned long len_a, len_b, len_k, len_g, len_xy, len_oid;
  unsigned long cofactor = 0, ecver = 0, pkver = 0, tmpoid[16], curveoid[16];
  /*oid_st oid;*/
  int err;

  if ((err = mp_init_multi(&prime, &order, &a, &b, &gx, &gy, NULL)) != CRYPT_OK)       return err;

  /* ### 1. try to load public key - no curve parameters just curve OID */

  len_xy = sizeof(bin_xy);
  err = der_decode_subject_public_key_info_ex(in, inlen, PKA_EC, bin_xy, &len_xy, LTC_ASN1_OBJECT_IDENTIFIER, curveoid, 16UL, &len_oid);
  if (err == CRYPT_OK) {
    /* load curve parameters for given curve OID */
    if ((err = _populate_dp_from_oid(curveoid, len_oid, dp)) != CRYPT_OK) { goto error; }
    /* load public key */
    if ((err = ecc_import_raw(bin_xy, len_xy, key, dp)) != CRYPT_OK) { goto error; }
    goto success;
  }

  /* ### 2. try to load public key - curve parameters included */

  /* ECParameters SEQUENCE */
  LTC_SET_ASN1(seq_ecparams, 0, LTC_ASN1_SHORT_INTEGER,     &ecver,       1UL);
  LTC_SET_ASN1(seq_ecparams, 1, LTC_ASN1_SEQUENCE,          seq_fieldid,  2UL);
  LTC_SET_ASN1(seq_ecparams, 2, LTC_ASN1_SEQUENCE,          seq_curve,    3UL);
  LTC_SET_ASN1(seq_ecparams, 3, LTC_ASN1_OCTET_STRING,      bin_g,        (unsigned long)2*ECC_MAXSIZE+1);
  LTC_SET_ASN1(seq_ecparams, 4, LTC_ASN1_INTEGER,           order,        1UL);
  LTC_SET_ASN1(seq_ecparams, 5, LTC_ASN1_SHORT_INTEGER,     &cofactor,    1UL);
  seq_ecparams[5].optional = 1;
  /* FieldID SEQUENCE */
  LTC_SET_ASN1(seq_fieldid,  0, LTC_ASN1_OBJECT_IDENTIFIER, tmpoid,       16UL);
  LTC_SET_ASN1(seq_fieldid,  1, LTC_ASN1_INTEGER,           prime,        1UL);
  /* Curve SEQUENCE */
  LTC_SET_ASN1(seq_curve,    0, LTC_ASN1_OCTET_STRING,      bin_a,        (unsigned long)ECC_MAXSIZE);
  LTC_SET_ASN1(seq_curve,    1, LTC_ASN1_OCTET_STRING,      bin_b,        (unsigned long)ECC_MAXSIZE);
  LTC_SET_ASN1(seq_curve,    2, LTC_ASN1_RAW_BIT_STRING,    bin_seed,     (unsigned long)8*128);
  seq_curve[2].optional = 1;
  /* try to load public key */
  len_xy = sizeof(bin_xy);
  err = der_decode_subject_public_key_info(in, inlen, PKA_EC, bin_xy, &len_xy, LTC_ASN1_SEQUENCE, seq_ecparams, 6);
  if (err == CRYPT_OK) {
    len_a = seq_curve[0].size;
    len_b = seq_curve[1].size;
    len_g = seq_ecparams[3].size;
    /* create bignums */
    if ((err = mp_read_unsigned_bin(a, bin_a, len_a)) != CRYPT_OK)                  { goto error; }
    if ((err = mp_read_unsigned_bin(b, bin_b, len_b)) != CRYPT_OK)                  { goto error; }
    if ((err = ecc_import_point(bin_g, len_g, prime, a, b, gx, gy)) != CRYPT_OK)    { goto error; }
    /* load curve parameters */
    if ((err = _populate_dp(a, b, prime, order, gx, gy, cofactor, dp)) != CRYPT_OK) { goto error; }
    /* load public key */
    if ((err = ecc_import_raw(bin_xy, len_xy, key, dp)) != CRYPT_OK)                { goto error; }
    goto success;
  }

  /* ### 3. try to load private key - no curve parameters just curve OID */

  /* ECPrivateKey SEQUENCE */
  LTC_SET_ASN1(seq_priv,     0, LTC_ASN1_SHORT_INTEGER,     &pkver,       1UL);
  LTC_SET_ASN1(seq_priv,     1, LTC_ASN1_OCTET_STRING,      bin_k,        (unsigned long)ECC_MAXSIZE);
  LTC_SET_ASN1(seq_priv,     2, LTC_ASN1_OBJECT_IDENTIFIER, curveoid,     16UL);
  LTC_SET_ASN1(seq_priv,     3, LTC_ASN1_RAW_BIT_STRING,    bin_xy,       (unsigned long)8*(2*ECC_MAXSIZE+2));
  seq_priv[2].tag = 0xA0; /* context specific 0 */
  seq_priv[3].tag = 0xA1; /* context specific 1 */
  /* try to load private key */
  err = der_decode_sequence(in, inlen, seq_priv, 4);
  if (err == CRYPT_OK) {
    /* load curve parameters for given curve OID */
    if ((err = _populate_dp_from_oid(curveoid, seq_priv[2].size, dp)) != CRYPT_OK) { goto error; }
    /* load private+public key */
    if ((err = ecc_import_raw(bin_k, seq_priv[1].size, key, dp)) != CRYPT_OK) { goto error; }
    goto success;
  }

  /* ### 4. try to load private key - curve parameters included */

  /* ECPrivateKey SEQUENCE */
  LTC_SET_ASN1(seq_priv,     0, LTC_ASN1_SHORT_INTEGER,     &pkver,       1UL);
  LTC_SET_ASN1(seq_priv,     1, LTC_ASN1_OCTET_STRING,      bin_k,        (unsigned long)ECC_MAXSIZE);
  LTC_SET_ASN1(seq_priv,     2, LTC_ASN1_SEQUENCE,          seq_ecparams, 6UL);
  LTC_SET_ASN1(seq_priv,     3, LTC_ASN1_RAW_BIT_STRING,    bin_xy,       (unsigned long)8*(2*ECC_MAXSIZE+2));
  seq_priv[2].tag = 0xA0; /* context specific 0 */
  seq_priv[3].tag = 0xA1; /* context specific 1 */
  /* ECParameters SEQUENCE */
  LTC_SET_ASN1(seq_ecparams, 0, LTC_ASN1_SHORT_INTEGER,     &ecver,       1UL);
  LTC_SET_ASN1(seq_ecparams, 1, LTC_ASN1_SEQUENCE,          seq_fieldid,  2UL);
  LTC_SET_ASN1(seq_ecparams, 2, LTC_ASN1_SEQUENCE,          seq_curve,    3UL);
  LTC_SET_ASN1(seq_ecparams, 3, LTC_ASN1_OCTET_STRING,      bin_g,        (unsigned long)2*ECC_MAXSIZE+1);
  LTC_SET_ASN1(seq_ecparams, 4, LTC_ASN1_INTEGER,           order,        1UL);
  LTC_SET_ASN1(seq_ecparams, 5, LTC_ASN1_SHORT_INTEGER,     &cofactor,    1UL);
  seq_ecparams[5].optional = 1;
  /* FieldID SEQUENCE */
  LTC_SET_ASN1(seq_fieldid,  0, LTC_ASN1_OBJECT_IDENTIFIER, tmpoid,       16UL);
  LTC_SET_ASN1(seq_fieldid,  1, LTC_ASN1_INTEGER,           prime,        1UL);
  /* Curve SEQUENCE */
  LTC_SET_ASN1(seq_curve,    0, LTC_ASN1_OCTET_STRING,      bin_a,        (unsigned long)ECC_MAXSIZE);
  LTC_SET_ASN1(seq_curve,    1, LTC_ASN1_OCTET_STRING,      bin_b,        (unsigned long)ECC_MAXSIZE);
  LTC_SET_ASN1(seq_curve,    2, LTC_ASN1_RAW_BIT_STRING,    bin_seed,     (unsigned long)8*128);
  seq_curve[2].optional = 1;
  /* try to load private key */
  err = der_decode_sequence(in, inlen, seq_priv, 4);
  if (err == CRYPT_OK) {
    len_k  = seq_priv[1].size;
    len_xy = seq_priv[3].size;
    len_a  = seq_curve[0].size;
    len_b  = seq_curve[1].size;
    len_g  = seq_ecparams[3].size;
    /* create bignums */
    if ((err = mp_read_unsigned_bin(a, bin_a, len_a)) != CRYPT_OK)                  { goto error; }
    if ((err = mp_read_unsigned_bin(b, bin_b, len_b)) != CRYPT_OK)                  { goto error; }
    if ((err = ecc_import_point(bin_g, len_g, prime, a, b, gx, gy)) != CRYPT_OK)    { goto error; }
    /* load curve parameters */
    if ((err = _populate_dp(a, b, prime, order, gx, gy, cofactor, dp)) != CRYPT_OK) { goto error; }
    /* load private+public key */
    if ((err = ecc_import_raw(bin_k, len_k, key, dp)) != CRYPT_OK)                  { goto error; }
    goto success;
  }

  /* ### 5. backward compatibility - try to load old-DER format */
  if ((err = ecc_import(in, inlen, key)) != CRYPT_OK)                               { goto error; }

success:
  err = CRYPT_OK;
error:
  mp_clear_multi(prime, order, a, b, gx, gy, NULL);
  return err;
}

#endif
