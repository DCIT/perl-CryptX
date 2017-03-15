/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 */

/* Implements ECC over Z/pZ for curve y^2 = x^3 + a*x + b
 *
 */

#include "tomcrypt.h"

#ifdef LTC_MECC

int ecc_export_point(unsigned char *out, unsigned long *outlen, void *x, void *y, unsigned long size, int compressed)
{
   int err;
   unsigned char buf[ECC_BUF_SIZE];
   unsigned long xsize, ysize;

   if (size > sizeof(buf)) return CRYPT_BUFFER_OVERFLOW;
   if ((xsize = mp_unsigned_bin_size(x)) > size) return CRYPT_BUFFER_OVERFLOW;
   if ((ysize = mp_unsigned_bin_size(y)) > size) return CRYPT_BUFFER_OVERFLOW;

   if(compressed) {
      if (*outlen < (1 + size)) {
         *outlen = 1 + size;
         return CRYPT_BUFFER_OVERFLOW;
      }
      /* store first byte */
      out[0] = mp_isodd(y) ? 0x03 : 0x02;
      /* pad and store x */
      zeromem(buf, sizeof(buf));
      if ((err = mp_to_unsigned_bin(x, buf + (size - xsize))) != CRYPT_OK) return err;
      XMEMCPY(out+1, buf, size);
      /* adjust outlen */
      *outlen = 1 + size;
   }
   else {
      if (*outlen < (1 + 2*size)) {
         *outlen = 1 + 2*size;
         return CRYPT_BUFFER_OVERFLOW;
      }
      /* store byte 0x04 */
      out[0] = 0x04;
      /* pad and store x */
      zeromem(buf, sizeof(buf));
      if ((err = mp_to_unsigned_bin(x, buf + (size - xsize))) != CRYPT_OK) return err;
      XMEMCPY(out+1, buf, size);
      /* pad and store y */
      zeromem(buf, sizeof(buf));
      if ((err = mp_to_unsigned_bin(y, buf + (size - ysize))) != CRYPT_OK) return err;
      XMEMCPY(out+1+size, buf, size);
      /* adjust outlen */
      *outlen = 1 + 2*size;
   }
   return CRYPT_OK;
}

/** Export raw public or private key (public keys = ANS X9.63 compressed or uncompressed; private keys = raw bytes)
  @param out    [out] destination of export
  @param outlen [in/out]  Length of destination and final output size
  @param type   PK_PRIVATE, PK_PUBLIC or PK_PUBLIC_COMPRESSED
  @param key    Key to export
  Return        CRYPT_OK on success
*/

int ecc_export_raw(unsigned char *out, unsigned long *outlen, int type, ecc_key *key)
{
   unsigned long size, ksize;
   int err;

   LTC_ARGCHK(key    != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   if (ltc_ecc_is_valid_idx(key->idx) == 0) {
      return CRYPT_INVALID_ARG;
   }
   size = key->dp->size;

   if (type == PK_PUBLIC_COMPRESSED) {
      if ((err = ecc_export_point(out, outlen, key->pubkey.x, key->pubkey.y, size, 1)) != CRYPT_OK) return err;
   }
   else if (type == PK_PUBLIC) {
      if ((err = ecc_export_point(out, outlen, key->pubkey.x, key->pubkey.y, size, 0)) != CRYPT_OK) return err;
   }
   else if (type == PK_PRIVATE) {
      if (key->type != PK_PRIVATE)                                                return CRYPT_PK_TYPE_MISMATCH;
      *outlen = size;
      if (size > *outlen)                                                         return CRYPT_BUFFER_OVERFLOW;
      if ((ksize = mp_unsigned_bin_size(key->k)) > size)                          return CRYPT_BUFFER_OVERFLOW;
      /* pad and store k */
      if ((err = mp_to_unsigned_bin(key->k, out + (size - ksize))) != CRYPT_OK)   return err;
      zeromem(out, size - ksize);
   }
   else {
      return CRYPT_INVALID_ARG;
   }

   return CRYPT_OK;
}

#endif
