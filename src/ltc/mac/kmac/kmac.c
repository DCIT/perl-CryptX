/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

/**
  @file kmac.c
  KMAC as defined in NIST SP 800-185
*/

#ifdef LTC_KMAC

/* Encoding helpers from NIST SP 800-185 2.3 - encoded output never exceeds 9 bytes (8 byte payload + 1 length byte) */
static unsigned long s_left_encode(ulong64 x, unsigned char *out)
{
   int i, n = 1;
   for (i = 7; i > 0; --i) {
      if ((x >> (i * 8)) & 0xff) {
         n = i + 1;
         break;
      }
   }
   out[0] = (unsigned char)n;
   for (i = 0; i < n; ++i) {
      out[1 + i] = (unsigned char)(x >> ((n - 1 - i) * 8));
   }
   return (unsigned long)(n + 1);
}

static unsigned long s_right_encode(ulong64 x, unsigned char *out)
{
   int i, n = 1;
   for (i = 7; i > 0; --i) {
      if ((x >> (i * 8)) & 0xff) {
         n = i + 1;
         break;
      }
   }
   for (i = 0; i < n; ++i) {
      out[i] = (unsigned char)(x >> ((n - 1 - i) * 8));
   }
   out[n] = (unsigned char)n;
   return (unsigned long)(n + 1);
}

static int s_feed_encode_string(hash_state *md, const unsigned char *s, unsigned long slen, unsigned long *total)
{
   unsigned char enc[9];
   unsigned long enclen;
   int err;
   enclen = s_left_encode((ulong64)slen * 8, enc);
   if ((err = sha3_process(md, enc, enclen)) != CRYPT_OK) return err;
   *total += enclen;
   if (slen != 0) {
      if ((err = sha3_process(md, s, slen)) != CRYPT_OK) return err;
      *total += slen;
   }
   return CRYPT_OK;
}

static int s_feed_bytepad_zero_fill(hash_state *md, unsigned long rate, unsigned long total)
{
   unsigned long pad = (rate - (total % rate)) % rate;
   if (pad != 0) {
      unsigned char zeros[168]; /* >= max SHAKE rate */
      XMEMSET(zeros, 0, sizeof(zeros));
      return sha3_process(md, zeros, pad);
   }
   return CRYPT_OK;
}

static int s_feed_bytepad_prefix(hash_state *md, unsigned long rate, unsigned long *total)
{
   unsigned char enc[9];
   unsigned long enclen = s_left_encode(rate, enc);
   int err = sha3_process(md, enc, enclen);
   if (err == CRYPT_OK) *total = enclen;
   return err;
}

/**
   Initialize a KMAC context

   @param st       The KMAC state
   @param variant  one of LTC_KMAC128, LTC_KMAC256, LTC_KMAC128_XOF, LTC_KMAC256_XOF
   @param key      The secret key
   @param keylen   The length of the secret key (octets)
   @param cust     Optional customization string (may be NULL when custlen == 0)
   @param custlen  Length of the customization string (octets)
   @return CRYPT_OK if successful
*/
int kmac_init(kmac_state *st, int variant,
              const unsigned char *key,  unsigned long keylen,
              const unsigned char *cust, unsigned long custlen)
{
   static const unsigned char kmac_name[4] = { 'K', 'M', 'A', 'C' };
   int err, num;
   unsigned long rate, total;

   LTC_ARGCHK(st  != NULL);
   LTC_ARGCHK(key != NULL || keylen  == 0);
   LTC_ARGCHK(cust != NULL || custlen == 0);

   switch (variant) {
      case LTC_KMAC128:     num = 128; st->xof = 0; rate = 168; break;
      case LTC_KMAC256:     num = 256; st->xof = 0; rate = 136; break;
      case LTC_KMAC128_XOF: num = 128; st->xof = 1; rate = 168; break;
      case LTC_KMAC256_XOF: num = 256; st->xof = 1; rate = 136; break;
      default:              return CRYPT_INVALID_ARG;
   }

   if ((err = sha3_shake_init(&st->sha3, num)) != CRYPT_OK) return err;

   /* bytepad(encode_string("KMAC") || encode_string(cust), rate) */
   if ((err = s_feed_bytepad_prefix(&st->sha3, rate, &total)) != CRYPT_OK) return err;
   if ((err = s_feed_encode_string(&st->sha3, kmac_name, sizeof(kmac_name), &total)) != CRYPT_OK) return err;
   if ((err = s_feed_encode_string(&st->sha3, cust, custlen, &total)) != CRYPT_OK) return err;
   if ((err = s_feed_bytepad_zero_fill(&st->sha3, rate, total)) != CRYPT_OK) return err;

   /* bytepad(encode_string(key), rate) */
   if ((err = s_feed_bytepad_prefix(&st->sha3, rate, &total)) != CRYPT_OK) return err;
   if ((err = s_feed_encode_string(&st->sha3, key, keylen, &total)) != CRYPT_OK) return err;
   if ((err = s_feed_bytepad_zero_fill(&st->sha3, rate, total)) != CRYPT_OK) return err;

   return CRYPT_OK;
}

/**
   Process data through KMAC

   @param st     The KMAC state
   @param in     The data to authenticate
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
int kmac_process(kmac_state *st, const unsigned char *in, unsigned long inlen)
{
   if (inlen == 0) return CRYPT_OK;
   LTC_ARGCHK(st != NULL);
   LTC_ARGCHK(in != NULL);
   return sha3_process(&st->sha3, in, inlen);
}

/**
   Terminate a KMAC session

   @param st      The KMAC state
   @param out     [out] The destination of the MAC
   @param outlen  [in/out] The requested length on entry, the produced length on return
   @return CRYPT_OK if successful
*/
int kmac_done(kmac_state *st, unsigned char *out, unsigned long *outlen)
{
   unsigned char enc[9];
   unsigned long enclen;
   int err;
   ulong64 L;

   LTC_ARGCHK(st     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* SP 800-185 4: append right_encode(L) where L is the requested output length in bits or right_encode(0) for the XOF flavour */
   L = st->xof ? 0 : (ulong64)(*outlen) * 8;
   enclen = s_right_encode(L, enc);
   if ((err = sha3_process(&st->sha3, enc, enclen)) != CRYPT_OK) return err;

   return sha3_shake_done_ex(&st->sha3, out, *outlen, 0x04);
}

#endif
