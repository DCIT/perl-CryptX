/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

#ifdef LTC_XCHACHA20

/**
   Encrypt (or decrypt) bytes of ciphertext (or plaintext) with XChaCha20
   @param key      The key
   @param keylen   The key length
   @param rounds   The number of rounds
   @param nonce    The nonce
   @param noncelen The nonce length, must be 24 (octets)
   @param datain   The plaintext (or ciphertext)
   @param datalen  The length of the input and output (octets)
   @param dataout  [out] The ciphertext (or plaintext)
   @return CRYPT_OK if successful
*/
int xchacha20_memory(const unsigned char *key,    unsigned long keylen,   unsigned long rounds,
                     const unsigned char *nonce,  unsigned long noncelen,
                     const unsigned char *datain, unsigned long datalen,  unsigned char *dataout)
{
   chacha_state st;
   int err;

   err = xchacha20_setup(&st, key, keylen, nonce, noncelen, rounds);
   if (err == CRYPT_OK) {
      err = chacha_crypt(&st, datain, datalen, dataout);
   }
   chacha_done(&st);
   return err;
}

#endif /* LTC_XCHACHA20 */
