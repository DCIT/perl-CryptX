/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/* The implementation is based on:
   draft-irtf-cfrg-xchacha, "XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305"
   RFC 8439, "ChaCha20 and Poly1305 for IETF Protocols"
*/

#ifdef LTC_XCHACHA20

#define QUARTERROUND(a,b,c,d) \
  x[a] += x[b]; x[d] = ROL(x[d] ^ x[a], 16); \
  x[c] += x[d]; x[b] = ROL(x[b] ^ x[c], 12); \
  x[a] += x[b]; x[d] = ROL(x[d] ^ x[a],  8); \
  x[c] += x[d]; x[b] = ROL(x[b] ^ x[c],  7);

/* ChaCha20 double-round without the final addition */
static void s_hchacha20(ulong32 *x, int rounds)
{
   int i;

   for (i = rounds; i > 0; i -= 2) {
      /* columnround */
      QUARTERROUND( 0, 4, 8,12)
      QUARTERROUND( 1, 5, 9,13)
      QUARTERROUND( 2, 6,10,14)
      QUARTERROUND( 3, 7,11,15)
      /* diagonalround */
      QUARTERROUND( 0, 5,10,15)
      QUARTERROUND( 1, 6,11,12)
      QUARTERROUND( 2, 7, 8,13)
      QUARTERROUND( 3, 4, 9,14)
   }
}

#undef QUARTERROUND

/**
   HChaCha20: derive a 256-bit subkey from a 256-bit key and 128-bit input.
   This is the ChaCha20 core (double-rounds) without the final addition step,
   extracting output from state positions {0,1,2,3,12,13,14,15}.
   @param out       [out] The derived 32-byte subkey
   @param outlen    The length of the output buffer, must be 32 (octets)
   @param key       The secret key
   @param keylen    The length of the secret key, must be 32 (octets)
   @param in        The 16-byte input (nonce or constant)
   @param inlen     The length of the input, must be 16 (octets)
   @param rounds    Number of rounds (must be evenly divisible by 2, default is 20)
   @return CRYPT_OK if successful
*/
int xchacha20_hchacha20(unsigned char *out,  unsigned long outlen,
                        const unsigned char *key, unsigned long keylen,
                        const unsigned char *in,  unsigned long inlen,
                        int rounds)
{
   const char * const constants = "expand 32-byte k";
   ulong32 x[16];

   LTC_ARGCHK(out != NULL);
   LTC_ARGCHK(outlen == 32);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(keylen == 32);
   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(inlen == 16);
   if (rounds == 0) rounds = 20;
   LTC_ARGCHK(rounds % 2 == 0);

   LOAD32L(x[ 0], constants +  0);
   LOAD32L(x[ 1], constants +  4);
   LOAD32L(x[ 2], constants +  8);
   LOAD32L(x[ 3], constants + 12);
   LOAD32L(x[ 4], key +  0);
   LOAD32L(x[ 5], key +  4);
   LOAD32L(x[ 6], key +  8);
   LOAD32L(x[ 7], key + 12);
   LOAD32L(x[ 8], key + 16);
   LOAD32L(x[ 9], key + 20);
   LOAD32L(x[10], key + 24);
   LOAD32L(x[11], key + 28);
   LOAD32L(x[12], in +  0);
   LOAD32L(x[13], in +  4);
   LOAD32L(x[14], in +  8);
   LOAD32L(x[15], in + 12);

   s_hchacha20(x, rounds);

   STORE32L(x[ 0], out +  0);
   STORE32L(x[ 1], out +  4);
   STORE32L(x[ 2], out +  8);
   STORE32L(x[ 3], out + 12);
   STORE32L(x[12], out + 16);
   STORE32L(x[13], out + 20);
   STORE32L(x[14], out + 24);
   STORE32L(x[15], out + 28);

   zeromem(x, sizeof(x));
   return CRYPT_OK;
}

/**
   Initialize an XChaCha20 context (HChaCha20 subkey derivation + ChaCha20 IETF setup)
   @param st        [out] The destination of the ChaCha20 state
   @param key       The secret key
   @param keylen    The length of the secret key, must be 32 (octets)
   @param nonce     The nonce
   @param noncelen  The length of the nonce, must be 24 (octets)
   @param rounds    Number of rounds (must be evenly divisible by 2, default is 20)
   @return CRYPT_OK if successful
*/
int xchacha20_setup(chacha_state *st, const unsigned char *key, unsigned long keylen,
                                      const unsigned char *nonce, unsigned long noncelen,
                                      int rounds)
{
   unsigned char subkey[32];
   unsigned char iv[12];
   int err;

   LTC_ARGCHK(st != NULL);
   LTC_ARGCHK(nonce != NULL);
   LTC_ARGCHK(noncelen == 24);

   /* HChaCha20: derive subkey from key and first 16 bytes of nonce */
   if ((err = xchacha20_hchacha20(subkey, 32, key, keylen, nonce, 16, rounds)) != CRYPT_OK) goto cleanup;

   /* set up ChaCha20 with the derived subkey */
   if ((err = chacha_setup(st, subkey, 32, rounds)) != CRYPT_OK) goto cleanup;

   /* build 12-byte IETF IV: 4 zero bytes + last 8 bytes of original nonce */
   XMEMSET(iv, 0, 4);
   XMEMCPY(iv + 4, nonce + 16, 8);
   if ((err = chacha_ivctr32(st, iv, 12, 0)) != CRYPT_OK) goto cleanup;

   /* mark as XChaCha20 */
   st->ivlen = 24;

cleanup:
   zeromem(subkey, sizeof(subkey));
   zeromem(iv, sizeof(iv));

   return err;
}

#endif /* LTC_XCHACHA20 */
