/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

#ifdef LTC_PADDING

/**
   Remove padding from your data

      This depads your data.

   @param data     The data to depad
   @param length   [in/out] The size of the data before/after (removing padding)
   @param mode     One of the LTC_PAD_xx flags
   @return CRYPT_OK on success
*/
int padding_depad(const unsigned char *data, unsigned long *length, unsigned long mode)
{
   unsigned long padded_length, unpadded_length, n;
   unsigned char pad, data_xor_pad = 0;
   enum padding_type type;

   LTC_ARGCHK(data   != NULL);
   LTC_ARGCHK(length != NULL);

   padded_length = *length;

   type = mode & LTC_PAD_MASK;

   /* LTC_PAD_ZERO is the only mode where padding_pad() can produce a 0-byte output.
      Every other mode always emits at least one padding byte, so a 0-byte buffer is malformed.
   */
   if (padded_length == 0 && type != LTC_PAD_ZERO) {
      return CRYPT_INVALID_PACKET;
   }

   if (type < LTC_PAD_ONE_AND_ZERO) {
      pad = data[padded_length - 1];

      if (pad > padded_length || pad == 0)  {
         unpadded_length = padded_length - (padded_length > 16 ? padded_length - 16 : padded_length);
         data_xor_pad = 1;
      } else {
         unpadded_length = padded_length - pad;
      }
   } else {
      /* init pad to calm old compilers */
      pad = 0x0;
      unpadded_length = padded_length;
   }

   switch (type) {
      case LTC_PAD_ANSI_X923:
         pad = 0x0;
         /* FALLTHROUGH */
      case LTC_PAD_PKCS7:
         for (n = unpadded_length; n < padded_length - 1; ++n) {
            data_xor_pad |= data[n] ^ pad;
         }
         break;
#ifdef LTC_RNG_GET_BYTES
      case LTC_PAD_ISO_10126:
         /* nop */
         break;
#endif
      case LTC_PAD_SSH:
         pad = 0x1;
         for (n = unpadded_length; n < padded_length; ++n) {
            data_xor_pad |= data[n] ^ pad++;
         }
         break;
      case LTC_PAD_ONE_AND_ZERO:
         while (unpadded_length > 0 && data[unpadded_length - 1] != 0x80) {
            data_xor_pad |= data[unpadded_length - 1];
            unpadded_length--;
         }
         if (unpadded_length == 0) data_xor_pad |= 1;
         else unpadded_length--;
         if (data[unpadded_length] != 0x80) data_xor_pad |= 1;
         break;
      case LTC_PAD_ZERO:
      case LTC_PAD_ZERO_ALWAYS:
         while (unpadded_length > 0 && data[unpadded_length - 1] == 0x0) {
            unpadded_length--;
         }
         if (type == LTC_PAD_ZERO_ALWAYS) {
            if (unpadded_length == padded_length) return CRYPT_INVALID_PACKET;
            if (data[unpadded_length] != 0x0) return CRYPT_INVALID_PACKET;
         }
         break;
      default:
         return CRYPT_INVALID_ARG;
   }

   if (data_xor_pad != 0)
      return CRYPT_INVALID_PACKET;

   *length = unpadded_length;

   return CRYPT_OK;
}

#endif
