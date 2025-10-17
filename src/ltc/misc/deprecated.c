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

#endif /* LTC_NO_DEPRECATED_APIS */
