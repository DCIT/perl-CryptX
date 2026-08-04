/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/**
   @param sha512_224.c
   SHA512/224 hash included in sha512.c
*/

#include "tomcrypt_private.h"

#if defined(LTC_SHA512_224) && defined(LTC_SHA512)

const struct ltc_hash_descriptor sha512_224_portable_desc =
{
    "sha512-224",
    15,
    28,
    128,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 5,  },
   9,

    &sha512_224_init,
    &sha512_224_c_process,
    &sha512_224_c_done,
    &sha512_224_c_test,
    NULL
};

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (28 bytes)
   @return CRYPT_OK if successful
*/
int sha512_224_c_done(hash_state * md, unsigned char *out)
{
   unsigned char buf[64];
   int err;

   LTC_ARGCHK(md  != NULL);
   LTC_ARGCHK(out != NULL);

   err = sha512_c_done(md, buf);
   XMEMCPY(out, buf, 28);
#ifdef LTC_CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return err;
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int sha512_224_c_test(void)
{
   return sha512_224_test_desc(&sha512_224_portable_desc, "SHA512-224 portable");
}

#endif /* defined(LTC_SHA512_224) && defined(LTC_SHA512) */
