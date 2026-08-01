/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/**
   @param sha224.c
   LTC_SHA-224 new NIST standard based off of LTC_SHA-256 truncated to 224 bits (Tom St Denis)
*/

#include "tomcrypt_private.h"

#if defined(LTC_SHA224) && defined(LTC_SHA256) && defined(LTC_SHA224_X86) && defined(LTC_SHA256_X86)

const struct ltc_hash_descriptor sha224_x86_desc =
{
    "sha224",
    10,
    28,
    64,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 4,  },
   9,

    &sha224_init,
    &sha224_x86_process,
    &sha224_x86_done,
    &sha224_x86_test,
    NULL
};

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (28 bytes)
   @return CRYPT_OK if successful
*/
int sha224_x86_done(hash_state * md, unsigned char *out)
{
    unsigned char buf[32];
    int err;

    LTC_ARGCHK(md  != NULL);
    LTC_ARGCHK(out != NULL);

    err = sha256_x86_done(md, buf);
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
int sha224_x86_test(void)
{
   return sha224_test_desc(&sha224_x86_desc, "SHA224 x86");
}

#endif /* defined(LTC_SHA224) && defined(LTC_SHA256) */

