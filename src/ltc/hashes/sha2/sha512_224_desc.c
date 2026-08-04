/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file sha512_224_desc.c
   SHA512/224 multiplexer between the portable and the x86 implementation
*/

#if defined(LTC_SHA512_224) && defined(LTC_SHA512)

const struct ltc_hash_descriptor sha512_224_desc =
{
    "sha512-224",
    15,
    28,
    128,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 5,  },
   9,

    &sha512_224_init,
    &sha512_process,
    &sha512_224_done,
    &sha512_224_test,
    NULL
};

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha512_224_init(hash_state * md)
{
    LTC_ARGCHK(md != NULL);

    md->sha512.curlen = 0;
    md->sha512.length = 0;
    md->sha512.state[0] = CONST64(0x8C3D37C819544DA2);
    md->sha512.state[1] = CONST64(0x73E1996689DCD4D6);
    md->sha512.state[2] = CONST64(0x1DFAB7AE32FF9C82);
    md->sha512.state[3] = CONST64(0x679DD514582F9FCF);
    md->sha512.state[4] = CONST64(0x0F6D2B697BD44DA8);
    md->sha512.state[5] = CONST64(0x77E36F7304C48942);
    md->sha512.state[6] = CONST64(0x3F9D85A86A1D36C8);
    md->sha512.state[7] = CONST64(0x1112E6AD91D692A1);
    return CRYPT_OK;
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (28 bytes)
   @return CRYPT_OK if successful
*/
int sha512_224_done(hash_state * md, unsigned char *out)
{
#if defined LTC_SHA512_224_X86
    if(sha512ni_is_supported()) {
        return sha512_224_x86_done(md, out);
    }
#endif
    return sha512_224_c_done(md, out);
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int sha512_224_test(void)
{
   return sha512_224_test_desc(&sha512_224_desc, "SHA512-224");
}

int sha512_224_test_desc(const struct ltc_hash_descriptor *desc, const char *name)
{
#ifndef LTC_TEST
   LTC_UNUSED_PARAM(desc);
   LTC_UNUSED_PARAM(name);
   return CRYPT_NOP;
#else
  static const struct {
      const char *msg;
      unsigned char hash[28];
  } tests[] = {
    { "abc",
      { 0x46, 0x34, 0x27, 0x0F, 0x70, 0x7B, 0x6A, 0x54,
        0xDA, 0xAE, 0x75, 0x30, 0x46, 0x08, 0x42, 0xE2,
        0x0E, 0x37, 0xED, 0x26, 0x5C, 0xEE, 0xE9, 0xA4,
        0x3E, 0x89, 0x24, 0xAA }
    },
    { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      { 0x23, 0xFE, 0xC5, 0xBB, 0x94, 0xD6, 0x0B, 0x23,
        0x30, 0x81, 0x92, 0x64, 0x0B, 0x0C, 0x45, 0x33,
        0x35, 0xD6, 0x64, 0x73, 0x4F, 0xE4, 0x0E, 0x72,
        0x68, 0x67, 0x4A, 0xF9 }
    },
  };

  int i;
  unsigned char tmp[28];
  hash_state md;

  LTC_ARGCHK(desc != NULL);
  LTC_ARGCHK(desc->init != NULL);
  LTC_ARGCHK(desc->process != NULL);
  LTC_ARGCHK(desc->done != NULL);
  LTC_ARGCHK(name != NULL);

  for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
      desc->init(&md);
      desc->process(&md, (unsigned char*)tests[i].msg, (unsigned long)XSTRLEN(tests[i].msg));
      desc->done(&md, tmp);
      if (ltc_compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), name, i)) {
         return CRYPT_FAIL_TESTVECTOR;
      }
  }
  return CRYPT_OK;
#endif
}

#endif /* defined(LTC_SHA512_224) && defined(LTC_SHA512) */
