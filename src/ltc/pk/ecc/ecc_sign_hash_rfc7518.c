/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

/**
  Sign a message digest (RFC7518 format + recovery_id)
  @param in        The message digest to sign
  @param inlen     The length of the digest
  @param out       [out] The destination for the signature
  @param outlen    [in/out] The max size and resulting size of the signature
  @param opts      The signature options that shall be applied
  @param key       A private ECC key
  @return CRYPT_OK if successful
*/
int ecc_sign_hash_rfc7518_internal(const unsigned char *in,  unsigned long inlen,
                                         unsigned char *out, unsigned long *outlen,
                                         ltc_ecc_sig_opts *opts, const ecc_key *key)
{
   int err;
   void *r, *s;
   unsigned long pbytes, i;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* RFC7518 format - raw (r,s) */
   pbytes = ltc_mp_unsigned_bin_size(key->dp.order);
   if (*outlen < 2 * pbytes) {
      *outlen = 2 * pbytes;
      return CRYPT_BUFFER_OVERFLOW;
   }

   if ((err = ltc_mp_init_multi(&r, &s, LTC_NULL)) != CRYPT_OK) return err;
   if ((err = ecc_sign_hash_internal(in, inlen, r, s, opts, key)) != CRYPT_OK) goto error;

   zeromem(out, 2 * pbytes);
   *outlen = 2 * pbytes;
   i = ltc_mp_unsigned_bin_size(r);
   if ((err = ltc_mp_to_unsigned_bin(r, out + pbytes - i)) != CRYPT_OK) goto error;
   i = ltc_mp_unsigned_bin_size(s);
   err = ltc_mp_to_unsigned_bin(s, out + 2 * pbytes - i);

error:
   ltc_mp_deinit_multi(r, s, LTC_NULL);
   return err;
}

#endif
