/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#if defined(LTC_MECC)

typedef int (*ecc_sign_fn)(const unsigned char    *in,
                                 unsigned long     inlen,
                                 unsigned char    *out,
                                 unsigned long    *outlen,
                                 ltc_ecc_sig_opts *opts,
                           const       ecc_key    *key);

static const ecc_sign_fn s_ecc_sign_hash[] = {
#ifdef LTC_DER
                                [LTC_ECCSIG_ANSIX962] = ecc_sign_hash_x962,
#endif
                                [LTC_ECCSIG_RFC7518] = ecc_sign_hash_rfc7518_internal,
                                [LTC_ECCSIG_ETH27] = ecc_sign_hash_eth27,
#ifdef LTC_SSH
                                [LTC_ECCSIG_RFC5656] = ecc_sign_hash_rfc5656,
#endif
};

/**
  Sign a message digest (ANSI X9.62 format)
  @param in        The message digest to sign
  @param inlen     The length of the digest
  @param out       [out] The destination for the signature
  @param outlen    [in/out] The max size and resulting size of the signature
  @param opts      The signature options that shall be applied
  @param key       A private ECC key
  @return CRYPT_OK if successful
*/
int ecc_sign_hash_v2(const unsigned char    *in,
                        unsigned long     inlen,
                        unsigned char    *out,
                        unsigned long    *outlen,
                        ltc_ecc_sig_opts *opts,
                  const       ecc_key    *key)
{
   if (opts->type < 0 || opts->type >= LTC_ARRAY_SIZE(s_ecc_sign_hash))
      return CRYPT_PK_INVALID_TYPE;
   if (s_ecc_sign_hash[opts->type] == NULL)
      return CRYPT_PK_INVALID_TYPE;
   return s_ecc_sign_hash[opts->type](in, inlen, out, outlen, opts, key);
}

#endif
