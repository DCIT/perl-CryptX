#include "tomcrypt.h"

#ifdef LTC_BASE64

static const unsigned char map[256] = {
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, /*  0 - 11 */
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, /* 12 - 23 */
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, /* 24 - 35 */
255, 255, 255, 255, 255, 255, 255, 255, 255,  62, 255, 255, /* 36 - 47  +..[43]  /..[47]  -..[45] */ 
 52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255, /* 48 */
255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6, /* 60 */
  7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18, /* 72 */
 19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255,  63, /* 84  _..[95] */
255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36, /* 96 */
 37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
 49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255 };

/**
   base64url decode a block of memory
   @param in       The base64 data to decode
   @param inlen    The length of the base64 data
   @param out      [out] The destination of the binary decoded data
   @param outlen   [in/out] The max size and resulting size of the decoded data
   @return CRYPT_OK if successful
*/
int base64url_decode(const unsigned char *in,  unsigned long inlen, 
                        unsigned char *out, unsigned long *outlen)
{
   unsigned long t, x, y, z;
   unsigned char c;
   int           g;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   g = 3;
   for (x = y = z = t = 0; x < inlen; x++) {
       c = map[in[x]&0xFF];
       if (c == 255) continue;
       /* the final = symbols are read and used to trim the remaining bytes */
       if (c == 254) { 
          c = 0; 
          /* prevent g < 0 which would potentially allow an overflow later */
          if (--g < 0) {
             return CRYPT_INVALID_PACKET;
          }
       } else if (g != 3) {
          /* we only allow = to be at the end */
          return CRYPT_INVALID_PACKET;
       }

       t = (t<<6)|c;

       if (++y == 4) {
          if (z + g > *outlen) { 
             return CRYPT_BUFFER_OVERFLOW; 
          }
          out[z++] = (unsigned char)((t>>16)&255);
          if (g > 1) out[z++] = (unsigned char)((t>>8)&255);
          if (g > 2) out[z++] = (unsigned char)(t&255);
          y = t = 0;
       }
   }
   if (y != 0) {
       return CRYPT_INVALID_PACKET;
   }
   *outlen = z;
   return CRYPT_OK;
}

#endif
