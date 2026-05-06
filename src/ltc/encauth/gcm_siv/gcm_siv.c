/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file gcm_siv.c
  RFC 8452 - AES-GCM-SIV: Nonce Misuse-Resistant AEAD
*/

#ifdef LTC_GCM_SIV_MODE

/* Multiply by x in the GHASH field GF(2^128) defined by
   x^128 + x^7 + x^2 + x + 1, using GHASH's bit-byte ordering
   (bit 7 of byte 0 is x^0, bit 0 of byte 15 is x^127). This is used
   once during key derivation per RFC 8452 Appendix A: the POLYVAL
   authentication key is computed as mulX_GHASH(ByteReverse(H_polyval))
   so that GHASH multiplication can be reused for POLYVAL.
*/
static void s_mulx_ghash(unsigned char *b)
{
   unsigned int carry = b[15] & 1;
   int x;

   for (x = 15; x > 0; x--) {
      b[x] = (unsigned char)((b[x] >> 1) | ((b[x-1] & 1) << 7));
   }
   b[0] >>= 1;
   if (carry) b[0] ^= 0xe1;
}

typedef struct {
   unsigned char H[16]; /* GHASH-form authentication key */
   unsigned char S[16]; /* GHASH-form accumulator */
} polyval_state;

static void s_polyval_init(polyval_state *st, const unsigned char *auth_key)
{
   int i;

   for (i = 0; i < 16; i++) st->H[i] = auth_key[15 - i];
   s_mulx_ghash(st->H);
   zeromem(st->S, 16);
}

static void s_polyval_block(polyval_state *st, const unsigned char *X)
{
   unsigned char T[16];
   int i;

   for (i = 0; i < 16; i++) st->S[i] ^= X[15 - i];
   gcm_gf_mult(st->S, st->H, T);
   XMEMCPY(st->S, T, 16);
}

static void s_polyval_data(polyval_state *st, const unsigned char *data, unsigned long len)
{
   unsigned long full = len / 16;
   unsigned long rem  = len % 16;
   unsigned long i;
   unsigned char block[16];

   for (i = 0; i < full; i++) s_polyval_block(st, data + i * 16);
   if (rem) {
      zeromem(block, 16);
      XMEMCPY(block, data + full * 16, rem);
      s_polyval_block(st, block);
   }
}

static void s_polyval_done(polyval_state *st, unsigned char *out)
{
   int i;
   for (i = 0; i < 16; i++) out[i] = st->S[15 - i];
}

/* Derive the POLYVAL authentication key and the AES message-encryption key from K and N as specified
   in RFC 8452 Section 4. The cipher is scheduled with the message-encryption key in *enc_ecb on success
*/
static int s_gcm_siv_derive_keys(int cipher,
                                 const unsigned char *K, unsigned long keylen,
                                 const unsigned char *N,
                                 unsigned char *auth_key,
                                 unsigned char *enc_key,
                                 symmetric_ECB *enc_ecb)
{
   int err;
   unsigned char input[16], block[16];
   unsigned long ctr, num_blocks;
   symmetric_ECB ecb;

   if ((err = ecb_start(cipher, K, (int)keylen, 0, &ecb)) != CRYPT_OK) return err;

   XMEMCPY(input + 4, N, 12);

   /* counters 0..1 yield the 16-byte authentication key, counters 2.. yield the encryption key (16 or 32 bytes) */
   num_blocks = (keylen == 16) ? 4 : 6;
   for (ctr = 0; ctr < num_blocks; ctr++) {
      STORE32L((ulong32)ctr, input);
      if ((err = ecb_encrypt_block(input, block, &ecb)) != CRYPT_OK) goto cleanup;
      if (ctr < 2) {
         XMEMCPY(auth_key + 8 * ctr, block, 8);
      } else {
         XMEMCPY(enc_key + 8 * (ctr - 2), block, 8);
      }
   }

   err = ecb_start(cipher, enc_key, (int)keylen, 0, enc_ecb);

cleanup:
   ecb_done(&ecb);
#ifdef LTC_CLEAN_STACK
   zeromem(input, sizeof(input));
   zeromem(block, sizeof(block));
#endif
   return err;
}

/**
   AES-GCM-SIV one-shot encryption/decryption (RFC 8452).

   @param cipher     The index of the cipher (must be a 128-bit block cipher; AES per RFC)
   @param key        The 16- or 32-byte key
   @param keylen     The length of the key (16 or 32)
   @param nonce      The 12-byte nonce
   @param noncelen   The length of the nonce (must be 12)
   @param aad        The associated data
   @param aadlen     The length of the associated data
   @param in         The input  (plaintext  on encrypt, ciphertext on decrypt)
   @param inlen      The length of the input
   @param out        The output (ciphertext on encrypt, plaintext  on decrypt)
   @param tag        [in/out] The 16-byte tag (output on encrypt, input on decrypt)
   @param taglen     [in/out] The length of the tag (must be >= 16; set to 16 on output)
   @param direction  LTC_ENCRYPT or LTC_DECRYPT
   @return CRYPT_OK on success, CRYPT_ERROR on tag mismatch during decrypt
*/
int gcm_siv_memory(                int  cipher,
                   const unsigned char *key,    unsigned long  keylen,
                   const unsigned char *nonce,  unsigned long  noncelen,
                   const unsigned char *aad,    unsigned long  aadlen,
                         unsigned char *in,     unsigned long  inlen,
                         unsigned char *out,
                         unsigned char *tag,    unsigned long *taglen,
                                   int  direction)
{
   int err, ecb_started = 0, ctr_started = 0;
   unsigned char auth_key[16];
   unsigned char enc_key[32];
   unsigned char S[16], IC[16], expected_tag[16];
   unsigned char lenblk[16];
   const unsigned char *plaintext;
   symmetric_ECB enc_ecb;
   symmetric_CTR ctr;
   polyval_state pv;
   unsigned long i;

   LTC_ARGCHK(key    != NULL);
   LTC_ARGCHK(nonce  != NULL);
   LTC_ARGCHK(aad    != NULL || aadlen == 0);
   LTC_ARGCHK(in     != NULL || inlen == 0);
   LTC_ARGCHK(out    != NULL || inlen == 0);
   LTC_ARGCHK(tag    != NULL);
   LTC_ARGCHK(taglen != NULL);

   if ((err = cipher_is_valid(cipher)) != CRYPT_OK)  return err;
   if (cipher_descriptor[cipher].block_length != 16) return CRYPT_INVALID_CIPHER;
   if (keylen != 16 && keylen != 32)                 return CRYPT_INVALID_KEYSIZE;
   if (noncelen != 12)                               return CRYPT_INVALID_ARG;
   if (*taglen < 16) {
      *taglen = 16;
      return CRYPT_BUFFER_OVERFLOW;
   }

   if ((err = s_gcm_siv_derive_keys(cipher, key, keylen, nonce, auth_key, enc_key, &enc_ecb)) != CRYPT_OK) goto cleanup;
   ecb_started = 1;

   if (direction == LTC_DECRYPT) {
      /* CTR mode in RFC 8452: the supplied tag is the initial counter block with the MSB of the last
         byte forced to 1; only the first 4 bytes (interpreted as little-endian uint32) advance
      */
      XMEMCPY(IC, tag, 16);
      IC[15] |= 0x80;
      if ((err = ctr_start(cipher, IC, enc_key, (int)keylen, 0, CTR_COUNTER_LITTLE_ENDIAN | 4, &ctr)) != CRYPT_OK) goto cleanup;
      ctr_started = 1;
      if (inlen) {
         if ((err = ctr_decrypt(in, out, inlen, &ctr)) != CRYPT_OK) goto cleanup;
      }
      ctr_done(&ctr);
      ctr_started = 0;
      plaintext = out;
   }
   else {
      plaintext = in;
   }

   s_polyval_init(&pv, auth_key);
   s_polyval_data(&pv, aad, aadlen);
   s_polyval_data(&pv, plaintext, inlen);
   STORE64L((ulong64)aadlen * 8, lenblk);
   STORE64L((ulong64)inlen  * 8, lenblk + 8);
   s_polyval_block(&pv, lenblk);
   s_polyval_done(&pv, S);

   for (i = 0; i < 12; i++) S[i] ^= nonce[i];
   S[15] &= 0x7f;

   if ((err = ecb_encrypt_block(S, expected_tag, &enc_ecb)) != CRYPT_OK)  goto cleanup;

   if (direction == LTC_DECRYPT) {
      err = XMEM_NEQ(expected_tag, tag, 16);
      if (err != CRYPT_OK) {
         if (inlen) zeromem(out, inlen); /* tag mismatch: do not release plaintext */
         goto cleanup;
      }
   }
   else {
      XMEMCPY(IC, expected_tag, 16);
      IC[15] |= 0x80;
      if ((err = ctr_start(cipher, IC, enc_key, (int)keylen, 0, CTR_COUNTER_LITTLE_ENDIAN | 4, &ctr)) != CRYPT_OK) {
         goto cleanup;
      }
      ctr_started = 1;
      if (inlen) {
         if ((err = ctr_encrypt(in, out, inlen, &ctr)) != CRYPT_OK) goto cleanup;
      }
      XMEMCPY(tag, expected_tag, 16);
      *taglen = 16;
   }

cleanup:
   if (ctr_started) ctr_done(&ctr);
   if (ecb_started) ecb_done(&enc_ecb);
#ifdef LTC_CLEAN_STACK
   zeromem(auth_key, sizeof(auth_key));
   zeromem(enc_key, sizeof(enc_key));
   zeromem(S, sizeof(S));
   zeromem(IC, sizeof(IC));
   zeromem(expected_tag, sizeof(expected_tag));
   zeromem(lenblk, sizeof(lenblk));
   zeromem(&pv, sizeof(pv));
#endif
   return err;
}

#endif
