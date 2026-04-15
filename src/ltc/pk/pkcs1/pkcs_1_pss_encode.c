/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pkcs_1_pss_encode.c
  PKCS #1 PSS Signature Padding, Tom St Denis
*/

#ifdef LTC_PKCS_1

/**
   PKCS #1 v2.00 Signature Encoding
   @param msghash          The hash to encode
   @param msghashlen       The length of the hash (octets)
   @param params           The PKCS#1 operation's parameters
   @param modulus_bitlen   The bit length of the RSA modulus
   @param out              [out] The destination of the encoding
   @param outlen           [in/out] The max size and resulting size of the encoded data
   @return CRYPT_OK if successful
*/
int ltc_pkcs_1_pss_encode_mgf1(const unsigned char *msghash,       unsigned long  msghashlen,
                             ltc_rsa_op_parameters *params,
                                     unsigned long  modulus_bitlen,
                                     unsigned char *out,           unsigned long *outlen)
{
   unsigned char *DB, *mask, *salt, *hash;
   unsigned long x, y, hLen, modulus_len, saltlen;
   int           err;
   hash_state    md;
   ltc_rsa_op_checked op_checked = ltc_pkcs1_op_checked_init(params);

   LTC_ARGCHK(msghash != NULL);
   LTC_ARGCHK(params  != NULL);
   LTC_ARGCHK(out     != NULL);
   LTC_ARGCHK(outlen  != NULL);

   if ((err = rsa_key_valid_op(LTC_PKCS1_SIGN, &op_checked)) != CRYPT_OK) {
      return err;
   }

   hLen        = hash_descriptor[op_checked.hash_alg].hashsize;
   saltlen     = params->params.saltlen;
   modulus_bitlen--;
   modulus_len = (modulus_bitlen>>3) + (modulus_bitlen & 7 ? 1 : 0);

   /* check sizes */
   if ((saltlen > modulus_len) || (modulus_len < hLen + saltlen + 2)) {
      return CRYPT_PK_INVALID_SIZE;
   }

   /* allocate ram for DB/mask/salt/hash of size modulus_len */
   DB   = XMALLOC(modulus_len);
   mask = XMALLOC(modulus_len);
   salt = XMALLOC(modulus_len);
   hash = XMALLOC(modulus_len);
   if (DB == NULL || mask == NULL || salt == NULL || hash == NULL) {
      if (DB != NULL) {
         XFREE(DB);
      }
      if (mask != NULL) {
         XFREE(mask);
      }
      if (salt != NULL) {
         XFREE(salt);
      }
      if (hash != NULL) {
         XFREE(hash);
      }
      return CRYPT_MEM;
   }


   /* generate random salt */
   if (saltlen > 0) {
      if (prng_descriptor[params->wprng].read(salt, saltlen, params->prng) != saltlen) {
         err = CRYPT_ERROR_READPRNG;
         goto LBL_ERR;
      }
   }

   /* M = (eight) 0x00 || msghash || salt, hash = H(M) */
   if ((err = hash_descriptor[op_checked.hash_alg].init(&md)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   zeromem(DB, 8);
   if ((err = hash_descriptor[op_checked.hash_alg].process(&md, DB, 8)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[op_checked.hash_alg].process(&md, msghash, msghashlen)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[op_checked.hash_alg].process(&md, salt, saltlen)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[op_checked.hash_alg].done(&md, hash)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* generate DB = PS || 0x01 || salt, PS == modulus_len - saltlen - hLen - 2 zero bytes */
   x = 0;
   XMEMSET(DB + x, 0, modulus_len - saltlen - hLen - 2);
   x += modulus_len - saltlen - hLen - 2;
   DB[x++] = 0x01;
   XMEMCPY(DB + x, salt, saltlen);
   /* x += saltlen; */

   /* generate mask of length modulus_len - hLen - 1 from hash */
   if ((err = ltc_pkcs_1_mgf1(op_checked.mgf1_hash_alg, hash, hLen, mask, modulus_len - hLen - 1)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* xor against DB */
   for (y = 0; y < (modulus_len - hLen - 1); y++) {
      DB[y] ^= mask[y];
   }

   /* output is DB || hash || 0xBC */
   if (*outlen < modulus_len) {
      *outlen = modulus_len;
      err = CRYPT_BUFFER_OVERFLOW;
      goto LBL_ERR;
   }

   /* DB len = modulus_len - hLen - 1 */
   y = 0;
   XMEMCPY(out + y, DB, modulus_len - hLen - 1);
   y += modulus_len - hLen - 1;

   /* hash */
   XMEMCPY(out + y, hash, hLen);
   y += hLen;

   /* 0xBC */
   out[y] = 0xBC;

   /* now clear the 8*modulus_len - modulus_bitlen most significant bits */
   out[0] &= 0xFF >> ((modulus_len<<3) - modulus_bitlen);

   /* store output size */
   *outlen = modulus_len;
   err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(DB,   modulus_len);
   zeromem(mask, modulus_len);
   zeromem(salt, modulus_len);
   zeromem(hash, modulus_len);
#endif

   XFREE(hash);
   XFREE(salt);
   XFREE(mask);
   XFREE(DB);

   return err;
}

#endif /* LTC_PKCS_1 */
