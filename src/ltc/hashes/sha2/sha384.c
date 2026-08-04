/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/**
   @param sha384.c
   LTC_SHA384 hash included in sha512.c, Tom St Denis
*/

#include "tomcrypt_private.h"

#if defined(LTC_SHA384) && defined(LTC_SHA512)

const struct ltc_hash_descriptor sha384_portable_desc =
{
    "sha384",
    4,
    48,
    128,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 2,  },
   9,

    &sha384_init,
    &sha384_c_process,
    &sha384_c_done,
    &sha384_c_test,
    NULL
};

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (48 bytes)
   @return CRYPT_OK if successful
*/
int sha384_c_done(hash_state * md, unsigned char *out)
{
   unsigned char buf[64];
   int err;

   LTC_ARGCHK(md  != NULL);
   LTC_ARGCHK(out != NULL);

   err = sha512_c_done(md, buf);
   XMEMCPY(out, buf, 48);
#ifdef LTC_CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return err;
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int sha384_c_test(void)
{
   return sha384_test_desc(&sha384_portable_desc, "SHA384 portable");
}

#endif /* defined(LTC_SHA384) && defined(LTC_SHA512) */
