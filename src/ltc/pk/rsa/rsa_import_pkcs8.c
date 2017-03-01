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
#include "tomcrypt.h"

/**
  @file rsa_import_pkcs8.c
  Import a PKCS RSA key
*/

#ifdef LTC_MRSA

/* Public-Key Cryptography Standards (PKCS) #8:
 * Private-Key Information Syntax Specification Version 1.2
 * https://tools.ietf.org/html/rfc5208
 *
 * PrivateKeyInfo ::= SEQUENCE {
 *      version                   Version,
 *      privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
 *      privateKey                PrivateKey,
 *      attributes           [0]  IMPLICIT Attributes OPTIONAL }
 * where:
 * - Version ::= INTEGER
 * - PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
 * - PrivateKey ::= OCTET STRING
 * - Attributes ::= SET OF Attribute
 *
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 *        encryptionAlgorithm  EncryptionAlgorithmIdentifier,
 *        encryptedData        EncryptedData }
 * where:
 * - EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * - EncryptedData ::= OCTET STRING
 */

/*
 * This PKCS12 key derivation code comes from BouncyCastle.
 *
 * @param idByte         1 == key, 2 == iv
 * @param n              keysize or ivsize
 * @param salt           8 byte salt
 * @param password       password
 * @param iterationCount iteration-count
 * @param md             The message digest to use
 * @return byte[] the derived key
 */

/*
pkcs12(int idByte, int n, byte[] salt, byte[] password, int iterationCount, MessageDigest md)
*/

int rsa_import_pkcs8(unsigned char *in, unsigned long inlen, rsa_key *key)
{
   int            err;
   void           *zero, *iter;
   unsigned char  *buf1=NULL, *buf2=NULL;
   unsigned long  buf1len, buf2len;
   unsigned long  oid[16];
   oid_st         rsaoid;
   ltc_asn1_list  alg_seq[2], top_seq[3];
   ltc_asn1_list  alg_seq_e[2], key_seq_e[2], top_seq_e[2];
   unsigned char  *decrypted=NULL;
   unsigned long  decryptedlen;

   LTC_ARGCHK(in          != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* get RSA alg oid */
   err = pk_get_oid(PKA_RSA, &rsaoid);
   if (err != CRYPT_OK) { return err; }

   /* alloc buffers */
   buf1len = inlen; /* approx. */
   buf1 = XCALLOC(1, buf1len);
   if (buf1 == NULL) { err = CRYPT_MEM; goto LBL_FREE; }
   buf2len = inlen; /* approx. */
   buf2 = XCALLOC(1, buf2len);
   if (buf2 == NULL) { err = CRYPT_MEM; goto LBL_FREE; }

   /* init key */
   err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, &zero, &iter, NULL);
   if (err != CRYPT_OK) { return err; }

   /* try to decode encrypted priv key */
   LTC_SET_ASN1(key_seq_e, 0, LTC_ASN1_OCTET_STRING, buf1, buf1len);
   LTC_SET_ASN1(key_seq_e, 1, LTC_ASN1_INTEGER, iter, 1UL);
   LTC_SET_ASN1(alg_seq_e, 0, LTC_ASN1_OBJECT_IDENTIFIER, oid, 16UL);
   LTC_SET_ASN1(alg_seq_e, 1, LTC_ASN1_SEQUENCE, key_seq_e, 2UL);
   LTC_SET_ASN1(top_seq_e, 0, LTC_ASN1_SEQUENCE, alg_seq_e, 2UL);
   LTC_SET_ASN1(top_seq_e, 1, LTC_ASN1_OCTET_STRING, buf2, buf2len);
   err=der_decode_sequence(in, inlen, top_seq_e, 2UL);
   if (err == CRYPT_OK) {
     /* XXX: TODO encrypted pkcs8 not supported */
     /* fprintf(stderr, "decrypt: iter=%ld salt.len=%ld encdata.len=%ld\n", mp_get_int(iter), key_seq_e[0].size, top_seq_e[1].size); */
     err = CRYPT_PK_INVALID_TYPE;
     goto LBL_ERR;
   }
   else {
     decrypted    = in;
     decryptedlen = inlen;
   }

   /* try to decode unencrypted priv key */
   LTC_SET_ASN1(alg_seq, 0, LTC_ASN1_OBJECT_IDENTIFIER, oid, 16UL);
   LTC_SET_ASN1(alg_seq, 1, LTC_ASN1_NULL, NULL, 0UL);
   LTC_SET_ASN1(top_seq, 0, LTC_ASN1_INTEGER, zero, 1UL);
   LTC_SET_ASN1(top_seq, 1, LTC_ASN1_SEQUENCE, alg_seq, 2UL);
   LTC_SET_ASN1(top_seq, 2, LTC_ASN1_OCTET_STRING, buf1, buf1len);
   err=der_decode_sequence(decrypted, decryptedlen, top_seq, 3UL);
   if (err != CRYPT_OK) { goto LBL_ERR; }

   /* check alg oid */
   if ((alg_seq[0].size != rsaoid.OIDlen) ||
        XMEMCMP(rsaoid.OID, alg_seq[0].data, rsaoid.OIDlen * sizeof(rsaoid.OID[0]))) {
        err = CRYPT_PK_INVALID_TYPE;
        goto LBL_ERR;
   }

   err = der_decode_sequence_multi(buf1, top_seq[2].size,
                                   LTC_ASN1_INTEGER, 1UL, zero,
                                   LTC_ASN1_INTEGER, 1UL, key->N,
                                   LTC_ASN1_INTEGER, 1UL, key->e,
                                   LTC_ASN1_INTEGER, 1UL, key->d,
                                   LTC_ASN1_INTEGER, 1UL, key->p,
                                   LTC_ASN1_INTEGER, 1UL, key->q,
                                   LTC_ASN1_INTEGER, 1UL, key->dP,
                                   LTC_ASN1_INTEGER, 1UL, key->dQ,
                                   LTC_ASN1_INTEGER, 1UL, key->qP,
                                   LTC_ASN1_EOL,     0UL, NULL);
   if (err != CRYPT_OK) { goto LBL_ERR; }
   mp_clear_multi(zero, iter, NULL);
   key->type = PK_PRIVATE;
   err = CRYPT_OK;
   goto LBL_FREE;

LBL_ERR:
   mp_clear_multi(key->d, key->e, key->N, key->dQ, key->dP, key->qP, key->p, key->q, zero, iter, NULL);

LBL_FREE:
   if (buf2 != NULL) XFREE(buf2);
   if (buf1 != NULL) XFREE(buf1);

   return err;
}

#endif /* LTC_MRSA */
