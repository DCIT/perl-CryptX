/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifndef LTC_NO_DEPRECATED_APIS

#ifdef LTC_MECC
/**
  Sign a message digest (ANSI X9.62 format)
  @param in        The message digest to sign
  @param inlen     The length of the digest
  @param out       [out] The destination for the signature
  @param outlen    [in/out] The max size and resulting size of the signature
  @param prng      An active PRNG state
  @param wprng     The index of the PRNG you wish to use
  @param key       A private ECC key
  @return CRYPT_OK if successful
*/
int ecc_sign_hash(const unsigned char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen,
                        prng_state *prng, int  wprng, const ecc_key *key)
{
   return ltc_ecc_sign_hash(in, inlen, out, outlen, prng, wprng, key);
}

/**
   Verify an ECC signature (ANSI X9.62 format)
   @param sig         The signature to verify
   @param siglen      The length of the signature (octets)
   @param hash        The hash (message digest) that was signed
   @param hashlen     The length of the hash (octets)
   @param stat        [out] Result of signature, 1==valid, 0==invalid
   @param key         The corresponding public ECC key
   @return CRYPT_OK if successful (even if the signature is not valid)
*/
int ecc_verify_hash(const unsigned char *sig,
                          unsigned long  siglen,
                    const unsigned char *hash,
                          unsigned long  hashlen,
                                    int *stat,
                    const       ecc_key *key)
{
   return ltc_ecc_verify_hash(sig, siglen, hash, hashlen, stat, key);
}

/**
  Sign a message digest (RFC7518 format)
  @param in        The message digest to sign
  @param inlen     The length of the digest
  @param out       [out] The destination for the signature
  @param outlen    [in/out] The max size and resulting size of the signature
  @param opts      The signature options that shall be applied
  @param key       A private ECC key
  @return CRYPT_OK if successful
*/
int ecc_sign_hash_rfc7518(const unsigned char *in,  unsigned long inlen,
                          unsigned char *out, unsigned long *outlen,
                          prng_state *prng, int  wprng, const ecc_key *key)
{
   return ltc_ecc_sign_hash_rfc7518(in, inlen, out, outlen, prng, wprng, key);
}

/**
   Verify an ECC signature (RFC7518 format)
   @param sig         The signature to verify
   @param siglen      The length of the signature (octets)
   @param hash        The hash (message digest) that was signed
   @param hashlen     The length of the hash (octets)
   @param stat        [out] Result of signature, 1==valid, 0==invalid
   @param key         The corresponding public ECC key
   @return CRYPT_OK if successful (even if the signature is not valid)
*/
int ecc_verify_hash_rfc7518(const unsigned char *sig,  unsigned long siglen,
                            const unsigned char *hash, unsigned long hashlen,
                            int *stat, const ecc_key *key)
{
   return ltc_ecc_verify_hash_rfc7518(sig, siglen, hash, hashlen, stat, key);
}
#endif /* LTC_MECC */

#ifdef LTC_MRSA
/**
    (PKCS #1 v2.0) OAEP pad then encrypt
    @param in          The plaintext
    @param inlen       The length of the plaintext (octets)
    @param out         [out] The ciphertext
    @param outlen      [in/out] The max size and resulting size of the ciphertext
    @param lparam      The system "lparam" for the encryption
    @param lparamlen   The length of lparam (octets)
    @param prng        An active PRNG
    @param prng_idx    The index of the desired prng
    @param hash_idx    The index of the desired hash
    @param padding     Type of padding (LTC_PKCS_1_OAEP or LTC_PKCS_1_V1_5)
    @param key         The RSA key to encrypt to
    @return CRYPT_OK if successful
*/
int rsa_encrypt_key_ex(const unsigned char *in,       unsigned long  inlen,
                             unsigned char *out,      unsigned long *outlen,
                       const unsigned char *lparam,   unsigned long  lparamlen,
                             prng_state    *prng,     int            prng_idx,
                             int            hash_idx, int            padding,
                       const rsa_key       *key)
{
   int err;
   ltc_rsa_op_parameters params;
   if ((err = rsa_args_to_op_params(lparam, lparamlen,
                                    prng, prng_idx,
                                    hash_idx,
                                    padding, 0,
                                    &params)) != CRYPT_OK) {
      return err;
   }
   return rsa_encrypt_key_v2(in, inlen, out, outlen, &params, key);
}

/**
   PKCS #1 decrypt then v1.5 or OAEP depad
   @param in          The ciphertext
   @param inlen       The length of the ciphertext (octets)
   @param out         [out] The plaintext
   @param outlen      [in/out] The max size and resulting size of the plaintext (octets)
   @param lparam      The system "lparam" value
   @param lparamlen   The length of the lparam value (octets)
   @param hash_idx    The hash algorithm used
   @param padding     Type of padding (LTC_PKCS_1_OAEP or LTC_PKCS_1_V1_5)
   @param stat        [out] Result of the decryption, 1==valid, 0==invalid
   @param key         The corresponding private RSA key
   @return CRYPT_OK if succcessul (even if invalid)
*/
int rsa_decrypt_key_ex(const unsigned char *in,             unsigned long  inlen,
                             unsigned char *out,            unsigned long *outlen,
                       const unsigned char *lparam,         unsigned long  lparamlen,
                             int            hash_idx,       int            padding,
                             int           *stat,     const rsa_key       *key)
{
   int err;
   ltc_rsa_op_parameters params;
   if ((err = rsa_args_to_op_params(lparam, lparamlen,
                                    NULL, -1,
                                    hash_idx,
                                    padding, 0,
                                    &params)) != CRYPT_OK) {
      return err;
   }
   return rsa_decrypt_key_v2(in, inlen, out, outlen, &params, stat, key);
}

/**
  PKCS #1 pad then sign
  @param in        The hash to sign
  @param inlen     The length of the hash to sign (octets)
  @param out       [out] The signature
  @param outlen    [in/out] The max size and resulting size of the signature
  @param padding   Type of padding (LTC_PKCS_1_PSS, LTC_PKCS_1_V1_5 or LTC_PKCS_1_V1_5_NA1)
  @param prng      An active PRNG state
  @param prng_idx  The index of the PRNG desired
  @param hash_idx  The index of the hash desired
  @param saltlen   The length of the salt desired (octets)
  @param key       The private RSA key to use
  @return CRYPT_OK if successful
*/
int rsa_sign_hash_ex(const unsigned char *in,       unsigned long  inlen,
                           unsigned char *out,      unsigned long *outlen,
                           int            padding,
                           prng_state    *prng,               int  prng_idx,
                           int            hash_idx, unsigned long  saltlen,
                     const rsa_key       *key)
{
   int err;
   ltc_rsa_op_parameters params;
   if ((err = rsa_args_to_op_params(NULL, 0,
                                    prng, prng_idx,
                                    hash_idx,
                                    padding, saltlen,
                                    &params)) != CRYPT_OK) {
      return err;
   }
   return rsa_sign_hash_v2(in, inlen, out, outlen, &params, key);
}

/**
  PKCS #1 de-sign then v1.5 or PSS depad
  @param sig              The signature data
  @param siglen           The length of the signature data (octets)
  @param hash             The hash of the message that was signed
  @param hashlen          The length of the hash of the message that was signed (octets)
  @param padding          Type of padding (LTC_PKCS_1_PSS, LTC_PKCS_1_V1_5 or LTC_PKCS_1_V1_5_NA1)
  @param hash_idx         The index of the desired hash
  @param saltlen          The length of the salt used during signature
  @param stat             [out] The result of the signature comparison, 1==valid, 0==invalid
  @param key              The public RSA key corresponding to the key that performed the signature
  @return CRYPT_OK on success (even if the signature is invalid)
*/
int rsa_verify_hash_ex(const unsigned char *sig,            unsigned long  siglen,
                       const unsigned char *hash,           unsigned long  hashlen,
                             int            padding,
                             int            hash_idx,       unsigned long  saltlen,
                             int           *stat,     const rsa_key       *key)
{
   int err;
   ltc_rsa_op_parameters params;
   if ((err = rsa_args_to_op_params(NULL, 0,
                                    NULL, -1,
                                    hash_idx,
                                    padding, saltlen,
                                    &params)) != CRYPT_OK) {
      return err;
   }
   return rsa_verify_hash_v2(sig, siglen, hash, hashlen, &params, stat, key);
}

int rsa_args_to_op_params(const unsigned char *lparam, unsigned long lparamlen,
                          prng_state *prng, int prng_idx, int hash_idx,
                          int padding, unsigned long saltlen,
                          ltc_rsa_op_parameters *params)
{
   int err;
   ltc_rsa_op_parameters p = {
                               .u.crypt.lparam = lparam,
                               .u.crypt.lparamlen = lparamlen,
                               .prng = prng,
                               .wprng = prng_idx,
                               .padding = padding,
                               .params.saltlen = saltlen,
                               .params.hash_idx = -1,
                               .params.mgf1_hash_idx = -1,
   };
   if ((err = hash_is_valid(hash_idx)) == CRYPT_OK) {
      p.params.hash_idx = hash_idx;
      p.params.mgf1_hash_idx = hash_idx;
      *params = p;
   } else if (padding == LTC_PKCS_1_V1_5 || padding == LTC_PKCS_1_V1_5_NA1) {
      /* PKCS#1 1.5 does not necessarily require a hash */
      err = CRYPT_OK;
      *params = p;
   }
   return err;
}
#endif /* LTC_MRSA */


#ifdef LTC_PKCS_1
/**
   Perform PKCS #1 MGF1 (internal)
   @param hash_idx    The index of the hash desired
   @param seed        The seed for MGF1
   @param seedlen     The length of the seed
   @param mask        [out] The destination
   @param masklen     The length of the mask desired
   @return CRYPT_OK if successful
*/
int pkcs_1_mgf1(int                  hash_idx,
                const unsigned char *seed, unsigned long seedlen,
                      unsigned char *mask, unsigned long masklen)
{
   return ltc_pkcs_1_mgf1(hash_idx, seed, seedlen, mask, masklen);
}
/**
  PKCS #1 v2.00 OAEP encode
  @param msg             The data to encode
  @param msglen          The length of the data to encode (octets)
  @param lparam          A session or system parameter (can be NULL)
  @param lparamlen       The length of the lparam data
  @param modulus_bitlen  The bit length of the RSA modulus
  @param prng            An active PRNG state
  @param prng_idx        The index of the PRNG desired
  @param hash_idx        The index of the hash desired
  @param out             [out] The destination for the encoded data
  @param outlen          [in/out] The max size and resulting size of the encoded data
  @return CRYPT_OK if successful
*/
int pkcs_1_oaep_encode(const unsigned char *msg,    unsigned long msglen,
                       const unsigned char *lparam, unsigned long lparamlen,
                             unsigned long modulus_bitlen, prng_state *prng,
                             int           prng_idx, int          hash_idx,
                             unsigned char *out,    unsigned long *outlen)
{
   int err;
   ltc_rsa_op_parameters params;
   if ((err = rsa_args_to_op_params(lparam, lparamlen,
                                    prng, prng_idx,
                                    hash_idx,
                                    LTC_PKCS_1_OAEP, 0,
                                    &params)) != CRYPT_OK) {
      return err;
   }
   return ltc_pkcs_1_oaep_encode(msg, msglen, &params, modulus_bitlen, out, outlen);
}

/**
   PKCS #1 v2.00 OAEP decode
   @param msg              The encoded data to decode
   @param msglen           The length of the encoded data (octets)
   @param lparam           The session or system data (can be NULL)
   @param lparamlen        The length of the lparam
   @param modulus_bitlen   The bit length of the RSA modulus
   @param mgf_hash         The hash algorithm used for the MGF
   @param lparam_hash      The hash algorithm used when hashing the lparam (can be -1)
   @param out              [out] Destination of decoding
   @param outlen           [in/out] The max size and resulting size of the decoding
   @param res              [out] Result of decoding, 1==valid, 0==invalid
   @return CRYPT_OK if successful
*/
int pkcs_1_oaep_decode(const unsigned char *msg,    unsigned long msglen,
                       const unsigned char *lparam, unsigned long lparamlen,
                             unsigned long modulus_bitlen, int hash_idx,
                             unsigned char *out,    unsigned long *outlen,
                             int           *res)
{
   int err;
   ltc_rsa_op_parameters params;
   if ((err = rsa_args_to_op_params(lparam, lparamlen,
                                    NULL, -1,
                                    hash_idx,
                                    LTC_PKCS_1_OAEP, 0,
                                    &params)) != CRYPT_OK) {
      return err;
   }
   return ltc_pkcs_1_oaep_decode(msg, msglen, &params, modulus_bitlen, out, outlen, res);
}

/**
   PKCS #1 v2.00 Signature Encoding using MGF1 and both hashes are the same
   @param msghash          The hash to encode
   @param msghashlen       The length of the hash (octets)
   @param saltlen          The length of the salt desired (octets)
   @param prng             An active PRNG context
   @param prng_idx         The index of the PRNG desired
   @param hash_idx         The index of the hash desired
   @param modulus_bitlen   The bit length of the RSA modulus
   @param out              [out] The destination of the encoding
   @param outlen           [in/out] The max size and resulting size of the encoded data
   @return CRYPT_OK if successful
*/
int pkcs_1_pss_encode(const unsigned char *msghash,  unsigned long msghashlen,
                            unsigned long saltlen,   prng_state   *prng,
                            int           prng_idx,  int           hash_idx,
                            unsigned long modulus_bitlen,
                            unsigned char *out,      unsigned long *outlen)
{
   int err;
   ltc_rsa_op_parameters params;
   if ((err = rsa_args_to_op_params(NULL, 0,
                                    prng, prng_idx,
                                    hash_idx,
                                    LTC_PKCS_1_PSS, saltlen,
                                    &params)) != CRYPT_OK) {
      return err;
   }
   return ltc_pkcs_1_pss_encode_mgf1(msghash, msghashlen, &params, modulus_bitlen, out, outlen);
}

/**
   PKCS #1 v2.00 PSS decode
   @param  msghash         The hash to verify
   @param  msghashlen      The length of the hash (octets)
   @param  sig             The signature data (encoded data)
   @param  siglen          The length of the signature data (octets)
   @param  saltlen         The length of the salt used (octets)
   @param  hash_idx        The index of the hash desired
   @param  modulus_bitlen  The bit length of the RSA modulus
   @param  res             [out] The result of the comparison, 1==valid, 0==invalid
   @return CRYPT_OK if successful (even if the comparison failed)
*/
int pkcs_1_pss_decode(const unsigned char *msghash, unsigned long msghashlen,
                      const unsigned char *sig,     unsigned long siglen,
                            unsigned long saltlen,  int           hash_idx,
                            unsigned long modulus_bitlen, int    *res)
{
   int err;
   ltc_rsa_op_parameters params;
   if ((err = rsa_args_to_op_params(NULL, 0,
                                    NULL, -1,
                                    hash_idx,
                                    LTC_PKCS_1_PSS, saltlen,
                                    &params)) != CRYPT_OK) {
      return err;
   }
   return ltc_pkcs_1_pss_decode_mgf1(msghash, msghashlen, sig, siglen, &params, modulus_bitlen, res);
}


/*! \brief PKCS #1 v1.5 encode.
 *
 *  \param msg              The data to encode
 *  \param msglen           The length of the data to encode (octets)
 *  \param block_type       Block type to use in padding (\sa ltc_pkcs_1_v1_5_blocks)
 *  \param modulus_bitlen   The bit length of the RSA modulus
 *  \param prng             An active PRNG state (only for LTC_PKCS_1_EME)
 *  \param prng_idx         The index of the PRNG desired (only for LTC_PKCS_1_EME)
 *  \param out              [out] The destination for the encoded data
 *  \param outlen           [in/out] The max size and resulting size of the encoded data
 *
 *  \return CRYPT_OK if successful
 */
int pkcs_1_v1_5_encode(const unsigned char *msg,
                             unsigned long  msglen,
                                       int  block_type,
                             unsigned long  modulus_bitlen,
                                prng_state *prng,
                                       int  prng_idx,
                             unsigned char *out,
                             unsigned long *outlen)
{
   return ltc_pkcs_1_v1_5_encode(msg, msglen,
                                 block_type, modulus_bitlen,
                                 prng, prng_idx,
                                 out, outlen);
}

/** @brief PKCS #1 v1.5 decode.
 *
 *  @param msg              The encoded data to decode
 *  @param msglen           The length of the encoded data (octets)
 *  @param block_type       Block type to use in padding (\sa ltc_pkcs_1_v1_5_blocks)
 *  @param modulus_bitlen   The bit length of the RSA modulus
 *  @param out              [out] Destination of decoding
 *  @param outlen           [in/out] The max size and resulting size of the decoding
 *  @param is_valid         [out] Boolean whether the padding was valid
 *
 *  @return CRYPT_OK if successful
 */
int pkcs_1_v1_5_decode(const unsigned char *msg,
                             unsigned long  msglen,
                                       int  block_type,
                             unsigned long  modulus_bitlen,
                             unsigned char *out,
                             unsigned long *outlen,
                                       int *is_valid)
{
   return ltc_pkcs_1_v1_5_decode(msg, msglen,
                                 block_type, modulus_bitlen,
                                 out, outlen,
                                 is_valid);
}
#endif /* LTC_PKCS_1 */

int compare_testvector(const void* is, const unsigned long is_len, const void* should, const unsigned long should_len, const char* what, int which)
{
   return ltc_compare_testvector(is, is_len, should, should_len, what, which);
}

#endif /* LTC_NO_DEPRECATED_APIS */
