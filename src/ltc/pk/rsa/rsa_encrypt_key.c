/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file rsa_encrypt_key.c
  RSA PKCS #1 encryption, Tom St Denis and Andreas Lange
*/

#ifdef LTC_MRSA
/**
   (PKCS #1 v2.0) OAEP or (PKCS #1 v1.5) EME pad then encrypt
   @param in          The plaintext
   @param inlen       The length of the plaintext (octets)
   @param out         [out] The ciphertext
   @param outlen      [in/out] The max size and resulting size of the ciphertext
   @param params      The RSA operation's parameters
   @param key         The RSA key to encrypt to
   @return CRYPT_OK if successful
*/
int rsa_encrypt_key_v2(const unsigned char   *in,     unsigned long  inlen,
                             unsigned char   *out,    unsigned long *outlen,
                       ltc_rsa_op_parameters *params,
                       const rsa_key         *key)
{
  int           err;
  unsigned long modulus_bitlen, modulus_bytelen, x;
  ltc_rsa_op_checked op_checked = ltc_rsa_op_checked_init(key, params);

  LTC_ARGCHK((inlen == 0) || (in != NULL));
  LTC_ARGCHK(out    != NULL);
  LTC_ARGCHK(outlen != NULL);

  if ((err = rsa_key_valid_op(LTC_RSA_ENCRYPT, &op_checked)) != CRYPT_OK) {
    return err;
  }

  /* get modulus len in bits */
  modulus_bitlen = ltc_mp_count_bits( (key->N));

  /* outlen must be at least the size of the modulus */
  modulus_bytelen = ltc_mp_unsigned_bin_size( (key->N));
  if (modulus_bytelen > *outlen) {
     *outlen = modulus_bytelen;
     return CRYPT_BUFFER_OVERFLOW;
  }

  if (params->padding == LTC_PKCS_1_OAEP) {
    /* OAEP pad the key */
    x = *outlen;
    if ((err = ltc_pkcs_1_oaep_encode(in, inlen, params, modulus_bitlen, out, &x)) != CRYPT_OK) {
       return err;
    }
  } else {
    /* PKCS #1 v1.5 pad the key */
    x = *outlen;
    if ((err = ltc_pkcs_1_v1_5_encode(in, inlen, LTC_PKCS_1_EME,
                                      modulus_bitlen, params->prng, params->wprng,
                                      out, &x)) != CRYPT_OK) {
      return err;
    }
  }

  /* rsa exptmod the OAEP or PKCS #1 v1.5 pad */
  return ltc_mp.rsa_me(out, x, out, outlen, PK_PUBLIC, key);
}

#endif /* LTC_MRSA */
