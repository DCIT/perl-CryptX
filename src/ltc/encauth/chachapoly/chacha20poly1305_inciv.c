/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_CHACHA20POLY1305_MODE

/**
  Reset ChaCha20Poly1305 state with incremented IV - used by https://shadowsocks.org/en/spec/AEAD-Ciphers.html
  @param st     The ChaCha20Poly1305 state
  @param iv     The IV data to add
  @param inlen  The length of the IV (must be 12 or 8)
  @return CRYPT_OK on success
 */
int chacha20poly1305_inciv(chacha20poly1305_state *st)
{
   int err;
   unsigned char tmp_iv[12];
   unsigned long ivlen;

   LTC_ARGCHK(st != NULL);

   ivlen = st->chacha.ivlen;
   if (ivlen == 12) {
      STORE32L(st->chacha.input[13], tmp_iv + 0);
      STORE32L(st->chacha.input[14], tmp_iv + 4);
      STORE32L(st->chacha.input[15], tmp_iv + 8);
      /* increment IV 96bit / 12 bytes */
      if (!++tmp_iv[0] && !++tmp_iv[1] && !++tmp_iv[2]  && !++tmp_iv[3] &&
          !++tmp_iv[4] && !++tmp_iv[5] && !++tmp_iv[6]  && !++tmp_iv[7] &&
          !++tmp_iv[8] && !++tmp_iv[9] && !++tmp_iv[10] && !++tmp_iv[11])
      {
         err = CRYPT_ERROR; /* IV overflow */
      }
      else {
         err = chacha20poly1305_setiv(st, tmp_iv, 12);
      }
   }
   else if (ivlen == 8) {
      STORE32L(st->chacha.input[14], tmp_iv + 0);
      STORE32L(st->chacha.input[15], tmp_iv + 4);
      /* increment IV 64bit / 8 bytes */
      if (!++tmp_iv[0] && !++tmp_iv[1] && !++tmp_iv[2]  && !++tmp_iv[3] &&
          !++tmp_iv[4] && !++tmp_iv[5] && !++tmp_iv[6]  && !++tmp_iv[7])
      {
         err = CRYPT_ERROR; /* IV overflow */
      }
      else {
         err = chacha20poly1305_setiv(st, tmp_iv, 8);
      }
   }
   else {
      err = CRYPT_ERROR; /* invalid IV length */
   }

   return err;
}

#endif
