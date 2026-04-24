/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_CHACHA20POLY1305_MODE

/**
  Set IV + counter data to the ChaCha20Poly1305 state and reset the context
  @param st     The ChaCha20Poly1305 state
  @param iv     The IV data to add
  @param ivlen  The length of the IV (must be 12 or 8, or 24 when LTC_XCHACHA20 is enabled)
  @return CRYPT_OK on success
 */
int chacha20poly1305_setiv(chacha20poly1305_state *st, const unsigned char *iv, unsigned long ivlen)
{
   chacha_state tmp_st;
   int i, err;
   unsigned char polykey[32];

   LTC_ARGCHK(st != NULL);
   LTC_ARGCHK(iv != NULL);
#ifdef LTC_XCHACHA20
   LTC_ARGCHK(ivlen == 12 || ivlen == 8 || ivlen == 24);
#else
   LTC_ARGCHK(ivlen == 12 || ivlen == 8);
#endif

#ifdef LTC_XCHACHA20
   if (ivlen == 24) {
      unsigned char orig_key[32];

      /* extract the original key from state (stored by chacha_setup via chacha20poly1305_init) */
      STORE32L(st->chacha.input[4],  orig_key +  0);
      STORE32L(st->chacha.input[5],  orig_key +  4);
      STORE32L(st->chacha.input[6],  orig_key +  8);
      STORE32L(st->chacha.input[7],  orig_key + 12);
      STORE32L(st->chacha.input[8],  orig_key + 16);
      STORE32L(st->chacha.input[9],  orig_key + 20);
      STORE32L(st->chacha.input[10], orig_key + 24);
      STORE32L(st->chacha.input[11], orig_key + 28);

      /* derive subkey via HChaCha20 and set up state with counter=0 */
      if ((err = xchacha20_setup(&st->chacha, orig_key, 32, iv, 24, 20)) != CRYPT_OK) {
         zeromem(orig_key, sizeof(orig_key));
         return err;
      }

      /* copy state to temporary for Poly1305 key derivation (counter=0) */
      for (i = 0; i < 16; i++) tmp_st.input[i] = st->chacha.input[i];
      tmp_st.input[12] = 0;
      tmp_st.rounds = st->chacha.rounds;
      tmp_st.ksleft = 0;
      tmp_st.ivlen  = 12;  /* use IETF counter mode for keystream generation */

      /* generate Poly1305 key from block 0 */
      if ((err = chacha_keystream(&tmp_st, polykey, 32)) != CRYPT_OK) {
         zeromem(orig_key, sizeof(orig_key));
         return err;
      }

      /* set main state counter to 1 for encryption */
      st->chacha.input[12] = 1;
      st->chacha.ksleft = 0;

      /* initialize Poly1305 */
      if ((err = poly1305_init(&st->poly, polykey, 32)) != CRYPT_OK) {
         zeromem(orig_key, sizeof(orig_key));
         return err;
      }
      st->ctlen  = 0;
      st->aadlen = 0;
      st->aadflg = 1;

      zeromem(orig_key, sizeof(orig_key));
      return CRYPT_OK;
   }
#endif

   /* set IV for chacha20 */
   if (ivlen == 12) {
      /* IV 96bit */
      if ((err = chacha_ivctr32(&st->chacha, iv, ivlen, 1)) != CRYPT_OK) return err;
   }
   else {
      /* IV 64bit */
      if ((err = chacha_ivctr64(&st->chacha, iv, ivlen, 1)) != CRYPT_OK) return err;
   }

   /* copy chacha20 key to temporary state */
   for(i = 0; i < 12; i++) tmp_st.input[i] = st->chacha.input[i];
   tmp_st.rounds = 20;
   /* set IV */
   if (ivlen == 12) {
      /* IV 32bit */
      if ((err = chacha_ivctr32(&tmp_st, iv, ivlen, 0)) != CRYPT_OK) return err;
   }
   else {
      /* IV 64bit */
      if ((err = chacha_ivctr64(&tmp_st, iv, ivlen, 0)) != CRYPT_OK) return err;
   }
   /* (re)generate new poly1305 key */
   if ((err = chacha_keystream(&tmp_st, polykey, 32)) != CRYPT_OK) return err;
   /* (re)initialise poly1305 */
   if ((err = poly1305_init(&st->poly, polykey, 32)) != CRYPT_OK) return err;
   st->ctlen  = 0;
   st->aadlen = 0;
   st->aadflg = 1;

   return CRYPT_OK;
}

#endif
