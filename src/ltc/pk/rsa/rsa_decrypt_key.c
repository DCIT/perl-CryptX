/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file rsa_decrypt_key.c
  RSA PKCS #1 Decryption, Tom St Denis and Andreas Lange
*/

#ifdef LTC_MRSA
/**
   Decrypt then (PKCS #1 v2.0) OAEP or (PKCS #1 v1.5) EME depad
   @param in          The ciphertext
   @param inlen       The length of the ciphertext (octets)
   @param out         [out] The plaintext
   @param outlen      [in/out] The max size and resulting size of the plaintext (octets)
   @param params      The RSA operation's parameters
   @param stat        [out] Result of the decryption, 1==valid, 0==invalid
   @param key         The corresponding private RSA key
   @return CRYPT_OK if succcessul (even if invalid)
*/
int rsa_decrypt_key_v2(const unsigned char *in,             unsigned long  inlen,
                             unsigned char *out,            unsigned long *outlen,
                     ltc_rsa_op_parameters *params,
                             int           *stat,     const rsa_key       *key)
{
  int           err;
  unsigned char *tmp;
  unsigned long modulus_bitlen, modulus_bytelen, x;
  ltc_rsa_op_checked op_checked = ltc_rsa_op_checked_init(key, params);

  LTC_ARGCHK(in     != NULL);
  LTC_ARGCHK(out    != NULL);
  LTC_ARGCHK(outlen != NULL);
  LTC_ARGCHK(stat   != NULL);

  /* default to invalid */
  *stat = 0;

  /* valid padding? */
  if ((err = rsa_key_valid_op(LTC_RSA_DECRYPT, &op_checked)) != CRYPT_OK) {
    return err;
  }

  /* get modulus len in bits */
  modulus_bitlen = ltc_mp_count_bits( (key->N));

  /* outlen must be at least the size of the modulus */
  modulus_bytelen = ltc_mp_unsigned_bin_size( (key->N));
  if (modulus_bytelen != inlen) {
     return CRYPT_INVALID_PACKET;
  }

  /* allocate ram */
  tmp = XMALLOC(inlen);
  if (tmp == NULL) {
     return CRYPT_MEM;
  }

  /* rsa exptmod the packet */
  x = inlen;
  if ((err = ltc_mp.rsa_me(in, inlen, tmp, &x, PK_PRIVATE, key)) != CRYPT_OK) {
     XFREE(tmp);
     return err;
  }

  if (params->padding == LTC_PKCS_1_OAEP) {
    /* now OAEP depad the packet */
    err = ltc_pkcs_1_oaep_decode(tmp, x, params, modulus_bitlen, out, outlen, stat);
  } else {
    /* now PKCS #1 v1.5 depad the packet */
    err = ltc_pkcs_1_v1_5_decode(tmp, x, LTC_PKCS_1_EME, modulus_bitlen, out, outlen, stat);
  }

  XFREE(tmp);
  return err;
}

#endif /* LTC_MRSA */
