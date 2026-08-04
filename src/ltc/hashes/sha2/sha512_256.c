/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/**
   @param sha512_256.c
   SHA512/256 hash included in sha512.c
*/

#include "tomcrypt_private.h"

#if defined(LTC_SHA512_256) && defined(LTC_SHA512)

const struct ltc_hash_descriptor sha512_256_portable_desc =
{
    "sha512-256",
    16,
    32,
    128,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 6,  },
   9,

    &sha512_256_init,
    &sha512_256_c_process,
    &sha512_256_c_done,
    &sha512_256_c_test,
    NULL
};

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (32 bytes)
   @return CRYPT_OK if successful
*/
int sha512_256_c_done(hash_state * md, unsigned char *out)
{
   unsigned char buf[64];
   int err;

   LTC_ARGCHK(md  != NULL);
   LTC_ARGCHK(out != NULL);

   err = sha512_c_done(md, buf);
   XMEMCPY(out, buf, 32);
#ifdef LTC_CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return err;
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int sha512_256_c_test(void)
{
   return sha512_256_test_desc(&sha512_256_portable_desc, "SHA512-256 portable");
}

#endif /* defined(LTC_SHA512_256) && defined(LTC_SHA512) */
