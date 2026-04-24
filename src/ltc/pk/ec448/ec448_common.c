/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ec448_common.c
  Shared field arithmetic and primitives for Ed448 and X448
  Field arithmetic over p = 2^448 - 2^224 - 1 (Goldilocks prime)
  Edwards curve: x^2 + y^2 = 1 + d*x^2*y^2, d = -39081
  RFC 8032 Section 5.2

  The field representation (16 limbs of 28 bits in long64) and the overall
  code structure follow the TweetNaCl pattern used for Curve25519 in
  ec25519/tweetnacl.c. TweetNaCl uses 16 limbs of 16 bits for GF(2^255-19);
  here the limb width is scaled to 28 bits so that 16 * 28 = 448. This keeps
  the same loop bounds, carry propagation shape and multiplication layout,
  trading performance for code simplicity.
*/

#ifdef LTC_CURVE448

/* Field element: 16 limbs of 28 bits each (16 * 28 = 448)
   Each limb nominally fits in 28 bits but may temporarily exceed that
   during computation; we use long64 for headroom
*/
typedef long64 gf448[16];

/* field constants */
static const gf448 gf448_0 = {0};
static const gf448 gf448_1 = {1};

/* d = -39081 mod p = p - 39081
   p in 28-bit limbs: all 0x0FFFFFFF except limb 8 = 0x0FFFFFFE
   d: limb 0 = 0x0FFFFFFF - 39081 = 0x0FFF6756, limb 8 = 0x0FFFFFFE, rest 0x0FFFFFFF
*/
static const gf448 ed448_d = {
   0x0FFF6756, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF,
   0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF,
   0x0FFFFFFE, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF,
   0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF
};

/* Ed448 base point in compressed bytes (57 bytes, little-endian y, sign bit in top of last byte) */
static const unsigned char ed448_base_point[57] = {
   0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98,
   0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
   0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a,
   0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
   0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b,
   0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
   0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69,
   0x00
};

/* Group order L (little-endian, 57 bytes) */
static const unsigned char ed448_order[57] = {
   0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
   0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
   0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
   0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
   0x00
};

/* Group order L as ulong64 array for modular reduction (byte-wise) */
static const ulong64 L448[57] = {
   0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
   0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
   0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
   0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
   0x00
};

/* Field arithmetic for GF(2^448 - 2^224 - 1) - 16 limbs, 28 bits each */

static LTC_INLINE void s_gf448_copy(gf448 r, const gf448 a)
{
   int i;
   for (i = 0; i < 16; ++i) r[i] = a[i];
}

/* Carry propagation
   Overflow from limb[15] wraps:  2^448 == 2^224 + 1 (mod p)
   So excess from limb 15 adds to limb 0 and limb 8
*/
static void s_gf448_carry(gf448 o)
{
   int i;
   long64 c;
   /* propagate carries from limb 0 to 14 */
   for (i = 0; i < 15; ++i) {
      c = o[i] >> 28;
      o[i+1] += c;
      o[i] -= c << 28;
   }
   /* limb 15 overflow: 2^(28*16) = 2^448 == 2^224 + 1 */
   c = o[15] >> 28;
   o[0]  += c;     /* + c * 1 */
   o[8]  += c;     /* + c * 2^224 */
   o[15] -= c << 28;
   /* one more pass to settle the extra from limb 0 and 8 */
   for (i = 0; i < 15; ++i) {
      c = o[i] >> 28;
      o[i+1] += c;
      o[i] -= c << 28;
   }
   c = o[15] >> 28;
   o[0]  += c;
   o[8]  += c;
   o[15] -= c << 28;
}

/* Conditional swap: if b==1, swap p and q; if b==0, no-op.  Constant-time */
static void s_gf448_cswap(gf448 p, gf448 q, int b)
{
   long64 t, i, mask = ~((long64)b - 1);
   for (i = 0; i < 16; ++i) {
      t = mask & (p[i] ^ q[i]);
      p[i] ^= t;
      q[i] ^= t;
   }
}

/* Pack a field element into 56 bytes (little-endian); fully reduces mod p first */
static void s_gf448_encode(unsigned char *o, const gf448 n)
{
   int i, j;
   long64 b;
   gf448 m, t;
   for (i = 0; i < 16; ++i) t[i] = n[i];

   /* carry 3 times to ensure all limbs in [0, 2^28) */
   s_gf448_carry(t);
   s_gf448_carry(t);
   s_gf448_carry(t);

   /* Subtract p and check borrow p: limbs 0..7 = 0x0FFFFFFF, limb 8 = 0x0FFFFFFE, limbs 9..15 = 0x0FFFFFFF */
   for (j = 0; j < 2; ++j) {
      m[0] = t[0] - (long64)0x0FFFFFFF;
      for (i = 1; i < 16; i++) {
         long64 sub;
         if (i == 8) sub = (long64)0x0FFFFFFE;
         else        sub = (long64)0x0FFFFFFF;
         m[i] = t[i] - sub - ((m[i-1] >> 28) & 1);
         m[i-1] &= 0x0FFFFFFF;
      }
      b = (m[15] >> 28) & 1;
      m[15] &= 0x0FFFFFFF;
      s_gf448_cswap(t, m, 1 - (int)b);
   }

   /* Serialize: 16 limbs * 28 bits = 448 bits = 56 bytes
      each limb contributes 28 bits = 3.5 bytes
      Limb i holds bits [28*i .. 28*i+27]
      Byte j holds bits [8*j .. 8*j+7]
   */
   XMEMSET(o, 0, 56);
   for (i = 0; i < 16; i++) {
      /* limb i holds bits starting at bit_offset = 28*i */
      unsigned long bit_off = (unsigned long)i * 28;
      unsigned long byte_off = bit_off / 8;
      unsigned long bit_shift = bit_off % 8;
      /* We need to spread 28 bits starting at byte_off, bit_shift */
      ulong64 val = (ulong64)(t[i] & 0x0FFFFFFF);
      val <<= bit_shift;
      for (j = 0; j < 5 && byte_off + (unsigned long)j < 56; j++) {
         o[byte_off + j] |= (unsigned char)(val & 0xFF);
         val >>= 8;
      }
   }
}

/* Unpack 56 bytes (little-endian) into a field element */
static void s_gf448_decode(gf448 o, const unsigned char *n)
{
   int i;
   XMEMSET(o, 0, sizeof(gf448));
   for (i = 0; i < 16; i++) {
      unsigned long bit_off = (unsigned long)i * 28;
      unsigned long byte_off = bit_off / 8;
      unsigned long bit_shift = bit_off % 8;
      ulong64 val = 0;
      int j;
      for (j = 0; j < 5 && byte_off + (unsigned long)j < 56; j++) {
         val |= ((ulong64)n[byte_off + j]) << (8 * (unsigned long)j);
      }
      val >>= bit_shift;
      o[i] = (long64)(val & 0x0FFFFFFF);
   }
}

/* constant-time equality check */
static int s_gf448_neq(const gf448 a, const gf448 b)
{
   unsigned char c[56], d[56];
   int i;
   ulong32 diff = 0;
   s_gf448_encode(c, a);
   s_gf448_encode(d, b);
   for (i = 0; i < 56; ++i) diff |= (ulong32)(c[i] ^ d[i]);
   return (1 & ((diff - 1) >> 8)) - 1;
}

/* return parity (low bit) of field element */
static unsigned char s_gf448_parity(const gf448 a)
{
   unsigned char d[56];
   s_gf448_encode(d, a);
   return d[0] & 1;
}

/* Addition */
static LTC_INLINE void s_gf448_add(gf448 o, const gf448 a, const gf448 b)
{
   int i;
   for (i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

/* Subtraction */
static LTC_INLINE void s_gf448_sub(gf448 o, const gf448 a, const gf448 b)
{
   int i;
   for (i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

/* Multiplication: o = a * b mod p
   Schoolbook 16x16 -> 31 limbs, then reduce using Goldilocks
   2^448 == 2^224 + 1, so for product limbs t[16..30]:
     t[i] += t[i+16]  (the "1" part)
     t[i+8] += t[i+16] (the "2^224" part, since limb 8 = 224 bits)
   Then carry
*/
static void s_gf448_mul(gf448 o, const gf448 a, const gf448 b)
{
   long64 i, j;
   long64 t[31];
   for (i = 0; i < 31; ++i) t[i] = 0;
   for (i = 0; i < 16; ++i)
      for (j = 0; j < 16; ++j)
         t[i + j] += a[i] * b[j];

   /* reduce t[16..30] */
   for (i = 14; i >= 0; --i) {
      t[i]     += t[i + 16];
      t[i + 8] += t[i + 16];
      t[i + 16] = 0;
   }
   /* Now t[0..15] holds the result, but t[8..15] may have gotten extra from
      t[16..23] additions.  t[15] overflow wraps via Goldilocks
   */
   for (i = 0; i < 16; ++i) o[i] = t[i];
   s_gf448_carry(o);
   s_gf448_carry(o);
}

/* Squaring */
static LTC_INLINE void s_gf448_sqr(gf448 o, const gf448 a)
{
   s_gf448_mul(o, a, a);
}

/* Inversion: o = a^(p-2) mod p
   p-2 = 2^448 - 2^224 - 3

   p-2 in binary (bit 447 to bit 0):
     bits 447..225: all 1 (223 ones)
     bit 224: 0
     bits 223..2: all 1 (222 ones)
     bit 1: 0
     bit 0: 1

   Square-and-multiply from MSB: start with a^1, then for each bit:
   square, then multiply by a if bit is 1
*/
static void s_gf448_inv(gf448 o, const gf448 inp)
{
   gf448 t;
   int i;

   s_gf448_copy(t, inp);

   /* Process from bit 446 down (bit 447 is the leading 1, we start with a^1) */
   /* bits 446..225: all 1 (222 bits) */
   for (i = 0; i < 222; i++) {
      s_gf448_sqr(t, t);
      s_gf448_mul(t, t, inp);
   }

   /* bit 224: 0 -> just square */
   s_gf448_sqr(t, t);

   /* bits 223..2: all 1 (222 bits) */
   for (i = 0; i < 222; i++) {
      s_gf448_sqr(t, t);
      s_gf448_mul(t, t, inp);
   }

   /* bit 1: 0 -> just square */
   s_gf448_sqr(t, t);

   /* bit 0: 1 -> square and multiply */
   s_gf448_sqr(t, t);
   s_gf448_mul(t, t, inp);

   s_gf448_copy(o, t);
}

/* Square root: o = a^((p+1)/4) mod p
   Since p == 3 (mod 4), this gives the square root of a when it exists
   (p+1)/4 = 2^446 - 2^222 = 2^222 * (2^224 - 1)
   In binary: 224 ones (bits 445..222) followed by 222 zeros (bits 221..0)
*/
static void s_gf448_sqrt(gf448 o, const gf448 inp)
{
   gf448 t;
   int i;

   s_gf448_copy(t, inp);

   /* bit 445 is the MSB; we start with a^1.  bits 444..222: all 1 (223 bits) */
   for (i = 0; i < 223; i++) {
      s_gf448_sqr(t, t);
      s_gf448_mul(t, t, inp);
   }

   /* bits 221..0: all 0 (222 bits) -> just square 222 times */
   for (i = 0; i < 222; i++) {
      s_gf448_sqr(t, t);
   }

   s_gf448_copy(o, t);
}


/* Edwards curve point operations
   Curve: x^2 + y^2 = 1 + d*x^2*y^2  (a = 1)
   Extended coordinates: (X : Y : Z : T) where x = X/Z, y = Y/Z, T = X*Y/Z
*/

/* Unified point addition (works for doubling too)
   Extended coordinates on x^2 + y^2 = 1 + d*x^2*y^2 (a=1):
     A = X1*X2, B = Y1*Y2, C = d*T1*T2, D = Z1*Z2
     E = (X1+Y1)(X2+Y2) - A - B
     F = D - C, G = D + C, H = B - A
     X3 = E*F, Y3 = G*H, T3 = E*H, Z3 = F*G
*/
static void s_ed448_point_add(gf448 p[4], gf448 q[4])
{
   gf448 a, b, c, d, e, f, g, h, t;

   s_gf448_mul(a, p[0], q[0]);        /* A = X1*X2 */
   s_gf448_mul(b, p[1], q[1]);        /* B = Y1*Y2 */
   s_gf448_mul(c, p[3], q[3]);
   s_gf448_mul(c, c, ed448_d);        /* C = d*T1*T2 */
   s_gf448_mul(d, p[2], q[2]);        /* D = Z1*Z2 */

   s_gf448_add(t, p[0], p[1]);        /* X1+Y1 */
   s_gf448_add(e, q[0], q[1]);        /* X2+Y2 */
   s_gf448_mul(e, t, e);              /* (X1+Y1)(X2+Y2) */
   s_gf448_sub(e, e, a);              /* - A */
   s_gf448_sub(e, e, b);              /* - B -> E */

   s_gf448_sub(f, d, c);              /* F = D - C */
   s_gf448_add(g, d, c);              /* G = D + C */
   s_gf448_sub(h, b, a);              /* H = B - A (since a=1) */

   s_gf448_mul(p[0], e, f);           /* X3 = E*F */
   s_gf448_mul(p[1], g, h);           /* Y3 = G*H */
   s_gf448_mul(p[2], f, g);           /* Z3 = F*G */
   s_gf448_mul(p[3], e, h);           /* T3 = E*H */
}

/* Conditional swap of two points (constant time) */
static void s_ed448_point_cswap(gf448 p[4], gf448 q[4], unsigned char b)
{
   int i;
   for (i = 0; i < 4; ++i) s_gf448_cswap(p[i], q[i], b);
}

/* Ed448 encoding: 57 bytes = 456 bits
   Bytes 0..55 contain the 448-bit little-endian y-coordinate.
   Bits 0..6 of byte 56 are zero for canonical encodings.
   Bit 7 of byte 56 stores the parity/sign bit of x.
*/
static void s_ed448_point_encode(unsigned char *r, gf448 p[4])
{
   gf448 tx, ty, zi;
   s_gf448_inv(zi, p[2]);
   s_gf448_mul(tx, p[0], zi);
   s_gf448_mul(ty, p[1], zi);
   s_gf448_encode(r, ty);
   /* bit 455 = bit 7 of byte 56 = sign of x */
   r[56] = 0;
   r[56] |= s_gf448_parity(tx) << 7;
}

/* Scalar multiplication: p = [s] * q; Constant-time double-and-add with conditional swap */
static void s_ed448_scalarmult(gf448 p[4], gf448 q[4], const unsigned char *s)
{
   int i;
   /* p = identity = (0, 1, 1, 0) */
   s_gf448_copy(p[0], gf448_0);
   s_gf448_copy(p[1], gf448_1);
   s_gf448_copy(p[2], gf448_1);
   s_gf448_copy(p[3], gf448_0);

   /* Ed448 scalars are 456 bits (57 bytes), but the group order is ~446 bits
      Clamped scalar has at most 448 bits (a[56]=0, a[55]|=0x80 sets bit 447)
      We scan all 456 bits to be safe
   */
   for (i = 455; i >= 0; --i) {
      unsigned char b = (s[i / 8] >> (i & 7)) & 1;
      s_ed448_point_cswap(p, q, b);
      s_ed448_point_add(q, p);
      s_ed448_point_add(p, p);
      s_ed448_point_cswap(p, q, b);
   }
}

/* Scalar base multiplication: p = [s] * B */
static void s_ed448_scalarmult_base(gf448 p[4], const unsigned char *s)
{
   gf448 q[4];

   /* decode base point: unpack y from first 56 bytes */
   s_gf448_decode(q[1], ed448_base_point);

   /* set Z = 1 */
   s_gf448_copy(q[2], gf448_1);

   /* recover x from y:
      x^2 + y^2 = 1 + d*x^2*y^2  =>  x^2 = (1 - y^2) / (1 - d*y^2) */
   {
      gf448 y2, num, den, den_inv, x2, x_cand;
      s_gf448_sqr(y2, q[1]);                 /* y^2 */
      s_gf448_sub(num, gf448_1, y2);         /* 1 - y^2 */
      s_gf448_mul(den, y2, ed448_d);         /* d * y^2 */
      s_gf448_sub(den, gf448_1, den);        /* 1 - d*y^2 */
      s_gf448_inv(den_inv, den);
      s_gf448_mul(x2, num, den_inv);         /* x^2 */

      /* x = x2^((p+1)/4) -- works since p == 3 mod 4 */
      s_gf448_sqrt(x_cand, x2);

      /* Check sign bit. The base point encoding has sign bit = 0 */
      if (s_gf448_parity(x_cand) != ((ed448_base_point[56] >> 7) & 1)) {
         /* negate x */
         s_gf448_sub(x_cand, gf448_0, x_cand);
      }
      s_gf448_copy(q[0], x_cand);
   }

   /* T = X * Y */
   s_gf448_mul(q[3], q[0], q[1]);

   s_ed448_scalarmult(p, q, s);
}

/* Decode a point from 57-byte encoding; returns 0 on success, -1 on failure */
static int s_ed448_point_decode(gf448 r[4], const unsigned char p[57])
{
   gf448 y2, num, den, den_inv, x2, x_cand, chk;
   unsigned char sign_bit;

   /* y from the first 56 bytes (448 bits) */
   s_gf448_decode(r[1], p);
   /* bit 7 of byte 56 is the x sign bit */
   sign_bit = (p[56] >> 7) & 1;

   s_gf448_copy(r[2], gf448_1);

   /* x^2 = (1 - y^2) / (1 - d*y^2) */
   s_gf448_sqr(y2, r[1]);
   s_gf448_sub(num, gf448_1, y2);         /* 1 - y^2 */
   s_gf448_mul(den, y2, ed448_d);         /* d * y^2 */
   s_gf448_sub(den, gf448_1, den);        /* 1 - d*y^2 */
   s_gf448_inv(den_inv, den);
   s_gf448_mul(x2, num, den_inv);

   /* Compute square root candidate */
   s_gf448_sqrt(x_cand, x2);

   /* Verify: x_cand^2 == x2 ? */
   s_gf448_sqr(chk, x_cand);
   if (s_gf448_neq(chk, x2)) {
      /* Not a valid point */
      return -1;
   }

   /* Adjust sign */
   if (s_gf448_parity(x_cand) != sign_bit) {
      s_gf448_sub(x_cand, gf448_0, x_cand);
   }

   s_gf448_copy(r[0], x_cand);
   s_gf448_mul(r[3], r[0], r[1]); /* T = X * Y */

   return 0;
}

/* Scalar arithmetic modulo L (group order) */

/* Reduce x[0..113] modulo L, store 57-byte result in r

   Uses the relation 2^448 == 4*c (mod L), where c = 2^446 - L is a 28-byte number
   Byte position i (for i >= 56) represents 2^(8*i) = 2^(8*(i-56)) * 2^448
     == 2^(8*(i-56)) * 4*c (mod L)
   So x[i] for i >= 56 folds into positions (i-56)..(i-56+27) as 4*x[i]*c[j]
*/
static void s_sc448_reduce(unsigned char *r, long64 x[114])
{
   long64 carry, i, j;
   int round;

   /* c = 2^446 - L (28 bytes, little-endian) */
   static const long64 C448[28] = {
      0x0D, 0xBB, 0xA7, 0x54, 0x6D, 0x3D, 0x87, 0xDC,
      0xAA, 0x70, 0x3A, 0x72, 0x8D, 0x3D, 0x93, 0xDE,
      0x6F, 0xC9, 0x29, 0x51, 0xB6, 0x24, 0xB1, 0x3B,
      0x16, 0xDC, 0x35, 0x83
   };

   /* Perform up to 4 rounds of folding to guarantee full reduction */
   for (round = 0; round < 4; round++) {
      /* Fold bytes 56..113 into lower positions */
      for (i = 113; i >= 56; --i) {
         if (x[i] == 0) continue;
         for (j = 0; j < 28; j++) {
            x[i - 56 + j] += 4 * x[i] * C448[j];
         }
         x[i] = 0;
      }

      /* Carry normalize from 0 to 113 */
      carry = 0;
      for (i = 0; i < 114; i++) {
         x[i] += carry;
         carry = x[i] >> 8;
         x[i] &= 255;
      }
      /* If no overflow into high bytes, we can stop early */
      if (carry == 0) {
         int done = 1;
         for (i = 56; i < 114; i++) {
            if (x[i] != 0) { done = 0; break; }
         }
         if (done) break;
      }
   }

   /* Now x[0..55] holds the value, x[56..113] should be zero
      Up to 4 conditional subtractions of L ensure x < L */
   for (round = 0; round < 4; round++) {
      long64 t[57], borrow;
      borrow = 0;
      for (i = 0; i < 57; i++) {
         t[i] = x[i] - (long64)L448[i] - borrow;
         borrow = (t[i] >> 63) & 1;
         t[i] &= 255;
      }
      /* If borrow=0 => x >= L, replace x with t. If borrow=1 => x < L, keep x */
      if (borrow == 0) {
         for (i = 0; i < 57; i++) x[i] = t[i];
      }
   }

   for (i = 0; i < 57; i++) {
      r[i] = (unsigned char)(x[i] & 255);
   }
}

static void s_sc448_reduce_buf(unsigned char *r)
{
   long64 x[114];
   int i;
   for (i = 0; i < 114; ++i) x[i] = (ulong64)r[i];
   for (i = 0; i < 114; ++i) r[i] = 0;
   s_sc448_reduce(r, x);
}

/* Check if scalar s < L (group order); returns 1 if s < L, 0 otherwise */
static int s_sc448_lt_order(const unsigned char *s)
{
   int i;
   /* s and ed448_order are both 57 bytes LE */
   for (i = 56; i >= 0; i--) {
      if (s[i] < ed448_order[i]) return 1;
      if (s[i] > ed448_order[i]) return 0;
   }
   return 0; /* equal means not strictly less */
}

/* Ed448 internal API functions */

/**
   Derive public key from secret key
   RFC 8032 Section 5.2.5:
     1. SHAKE256(sk, 57) -> 114 bytes
     2. Clamp first 57 bytes: a[0] &= 0xFC, a[55] |= 0x80, a[56] = 0
     3. pk = [a]B
*/
int ec448_sk_to_pk_internal(unsigned char *pk, const unsigned char *sk)
{
   unsigned char az[114];
   gf448 p[4];
   int err;

   { unsigned long azlen = 114; if ((err = sha3_shake_memory(256, sk, 57, az, &azlen)) != CRYPT_OK) return err; }

   /* clamp */
   az[0] &= 0xFC;
   az[55] |= 0x80;
   az[56] = 0;

   s_ed448_scalarmult_base(p, az);
   s_ed448_point_encode(pk, p);

   zeromem(az, sizeof(az));
   return CRYPT_OK;
}

/**
   Generate Ed448 keypair
*/
int ec448_keypair_internal(prng_state *prng, int wprng, unsigned char *pk, unsigned char *sk)
{
   int err;

   if ((err = prng_is_valid(wprng)) != CRYPT_OK) return err;

   if (prng_descriptor[wprng].read(sk, 57, prng) != 57) {
      return CRYPT_ERROR_READPRNG;
   }

   if ((err = ec448_sk_to_pk_internal(pk, sk)) != CRYPT_OK) {
      return err;
   }

   return CRYPT_OK;
}

/**
   Ed448 sign

   RFC 8032 Section 5.2.6:
     1. SHAKE256(sk, 57) -> (a, prefix) where a is clamped first 57 bytes
     2. r = SHAKE256(DOM4(0,ctx) || prefix || msg) mod L
     3. R = [r]B encoded
     4. h = SHAKE256(DOM4(0,ctx) || R || pk || msg) mod L
     5. S = (r + h*a) mod L
     6. sig = R || S (114 bytes)

   The sm buffer receives R || S || msg (smlen = mlen + 114)
   ctx/cs: DOM4 context; for plain Ed448, ctx=NULL, cs=0 but DOM4 is still prepended
*/
int ec448_sign_internal(unsigned char *sm, unsigned long long *smlen,
                      const unsigned char *m, unsigned long long mlen,
                      const unsigned char *sk, const unsigned char *pk,
                      const unsigned char *ctx, unsigned long long cs)
{
   unsigned char az[114], nonce[114], hram[114];
   long64 x[114];
   long64 i, j;
   gf448 p[4];
   int err;

   /* ctx/cs is a pre-built DOM4 prefix that gets prepended to all hashes
      The wrapper functions build it:
        ed448_sign    -> DOM4(0, "")
        ed448ctx_sign -> DOM4(0, ctx)
        ed448ph_sign  -> DOM4(1, ctx)
   */

   /* Hash secret key */
   { unsigned long azlen = 114; if ((err = sha3_shake_memory(256, sk, 57, az, &azlen)) != CRYPT_OK) return err; }

   /* Clamp scalar a */
   az[0] &= 0xFC;
   az[55] |= 0x80;
   az[56] = 0;

   /* Compute nonce r = SHAKE256(ctx || prefix || msg) mod L */
   /* ctx already contains DOM4 prefix from the wrapper */
   *smlen = mlen + 114;

   if (ctx != NULL && cs > 0) {
      hash_state md;
      if ((err = sha3_shake_init(&md, 256)) != CRYPT_OK) goto cleanup;
      if ((err = sha3_shake_process(&md, ctx, (unsigned long)cs)) != CRYPT_OK) goto cleanup;
      if ((err = sha3_shake_process(&md, az + 57, 57)) != CRYPT_OK) goto cleanup;
      if ((err = sha3_shake_process(&md, m, (unsigned long)mlen)) != CRYPT_OK) goto cleanup;
      if ((err = sha3_shake_done(&md, nonce, 114)) != CRYPT_OK) goto cleanup;
   }
   else {
      hash_state md;
      if ((err = sha3_shake_init(&md, 256)) != CRYPT_OK) goto cleanup;
      if ((err = sha3_shake_process(&md, az + 57, 57)) != CRYPT_OK) goto cleanup;
      if ((err = sha3_shake_process(&md, m, (unsigned long)mlen)) != CRYPT_OK) goto cleanup;
      if ((err = sha3_shake_done(&md, nonce, 114)) != CRYPT_OK) goto cleanup;
   }

   s_sc448_reduce_buf(nonce);

   /* R = [r]B */
   s_ed448_scalarmult_base(p, nonce);
   s_ed448_point_encode(sm, p);  /* sm[0..56] = R */

   /* Compute h = SHAKE256(ctx || R || pk || msg) mod L */
   {
      hash_state md;
      if ((err = sha3_shake_init(&md, 256)) != CRYPT_OK) goto cleanup;
      if (ctx != NULL && cs > 0) {
         if ((err = sha3_shake_process(&md, ctx, (unsigned long)cs)) != CRYPT_OK) goto cleanup;
      }
      if ((err = sha3_shake_process(&md, sm, 57)) != CRYPT_OK) goto cleanup;       /* R */
      if ((err = sha3_shake_process(&md, pk, 57)) != CRYPT_OK) goto cleanup;       /* pk */
      if ((err = sha3_shake_process(&md, m, (unsigned long)mlen)) != CRYPT_OK) goto cleanup;  /* msg */
      if ((err = sha3_shake_done(&md, hram, 114)) != CRYPT_OK) goto cleanup;
   }
   s_sc448_reduce_buf(hram);

   /* S = (r + h * a) mod L */
   for (i = 0; i < 114; ++i) x[i] = 0;
   for (i = 0; i < 57; ++i)  x[i] = (ulong64)nonce[i];
   for (i = 0; i < 57; ++i)
      for (j = 0; j < 57; ++j)
         x[i + j] += (long64)hram[i] * (long64)(ulong64)az[j];
   s_sc448_reduce(sm + 57, x);  /* sm[57..113] = S */

   err = CRYPT_OK;

cleanup:
   zeromem(az, sizeof(az));
   zeromem(nonce, sizeof(nonce));
   zeromem(hram, sizeof(hram));
   zeromem(x, sizeof(x));
   return err;
}

/**
   Ed448 verify

   RFC 8032 Section 5.2.7:
     1. Parse sig as R (57 bytes) || S (57 bytes)
     2. Decode R, pk as points
     3. Check S < L
     4. h = SHAKE256(DOM4(0,ctx) || R || pk || msg) mod L
     5. Check [S]B == R + [h]A

   sm = sig || msg (smlen = siglen + msglen, siglen = 114)
   Returns stat=1 if valid, stat=0 if invalid
*/
int ec448_verify_internal(int *stat, unsigned char *m, unsigned long long *mlen,
                          const unsigned char *sm, unsigned long long smlen,
                          const unsigned char *ctx, unsigned long long cs,
                          const unsigned char *pk)
{
   unsigned char hram[114];
   unsigned char t[57];
   gf448 p[4], q[4], r_point[4];
   unsigned long long i;
   int err;
   unsigned char s_bytes[57];

   *stat = 0;

   if (*mlen < smlen) return CRYPT_BUFFER_OVERFLOW;
   *mlen = (unsigned long long)-1;
   if (smlen < 114) return CRYPT_INVALID_ARG;

   /* Decode public key A */
   if (s_ed448_point_decode(q, pk) != 0) return CRYPT_ERROR;

   /* Copy sm to m for manipulation */
   XMEMMOVE(m, sm, (unsigned long)smlen);

   /* Extract S (bytes 57..113 of signature) */
   XMEMCPY(s_bytes, m + 57, 57);

   /* Check S < L */
   if (!s_sc448_lt_order(s_bytes)) {
      for (i = 0; i < smlen - 114; ++i) m[i] = 0;
      return CRYPT_OK;
   }

   /* Decode R (bytes 0..56 of signature) */
   if (s_ed448_point_decode(r_point, m) != 0) {
      for (i = 0; i < smlen - 114; ++i) m[i] = 0;
      return CRYPT_OK;
   }

   /* Replace S in m with pk for hashing: m = R || pk || msg */
   XMEMCPY(m + 57, pk, 57);

   /* h = SHAKE256(ctx || R || pk || msg) mod L */
   {
      hash_state md;
      if ((err = sha3_shake_init(&md, 256)) != CRYPT_OK) return err;
      if (ctx != NULL && cs > 0) {
         if ((err = sha3_shake_process(&md, ctx, (unsigned long)cs)) != CRYPT_OK) return err;
      }
      if ((err = sha3_shake_process(&md, m, (unsigned long)smlen)) != CRYPT_OK) return err;
      if ((err = sha3_shake_done(&md, hram, 114)) != CRYPT_OK) return err;
   }
   s_sc448_reduce_buf(hram);

   /* Compute [h]A */
   s_ed448_scalarmult(p, q, hram);

   /* Add R: p = R + [h]A */
   s_ed448_point_add(p, r_point);

   /* Compute [S]B */
   s_ed448_scalarmult_base(q, s_bytes);

   /* Compare: [S]B == R + [h]A */
   s_ed448_point_encode(t, q);
   {
      unsigned char t2[57];
      s_ed448_point_encode(t2, p);

      /* Constant-time comparison */
      {
         ulong32 diff = 0;
         int idx;
         for (idx = 0; idx < 57; idx++) diff |= (ulong32)(t[idx] ^ t2[idx]);
         if (diff == 0) {
            *stat = 1;
            smlen -= 114;
            XMEMMOVE(m, m + 114, (unsigned long)smlen);
            *mlen = smlen;
         }
         else {
            for (i = 0; i < smlen - 114; ++i) m[i] = 0;
            zeromem(m, (unsigned long)(smlen - 114));
         }
      }
   }

   return CRYPT_OK;
}

/* Ed448 prehash: SHAKE256(msg) truncated to 64 bytes */
int ec448_prehash_internal(unsigned char *out, const unsigned char *msg, unsigned long long msglen)
{
   unsigned long phlen = 64;
   return sha3_shake_memory(256, msg, (unsigned long)msglen, out, &phlen);
}


/* X448 scalar multiplication (RFC 7748 Montgomery ladder) */
int ec448_scalarmult_internal(unsigned char *out, const unsigned char *scalar, const unsigned char *point)
{
   unsigned char sk[56];
   gf448 x1, x2, z2, x3, z3;
   gf448 a, aa, b, bb, e, c, d, da, cb, t;
   static const gf448 a24 = {39081};
   int i;
   unsigned char swap = 0;

   /* clamp scalar */
   XMEMCPY(sk, scalar, 56);
   sk[0]  &= 252;
   sk[55] |= 128;

   /* decode u-coordinate */
   s_gf448_decode(x1, point);

   /* x_2 = 1, z_2 = 0, x_3 = u, z_3 = 1 */
   s_gf448_copy(x3, x1);
   s_gf448_copy(x2, gf448_1);
   s_gf448_copy(z2, gf448_0);
   s_gf448_copy(z3, gf448_1);

   for (i = 447; i >= 0; --i) {
      unsigned char k_t = (sk[i / 8] >> (i & 7)) & 1;
      swap ^= k_t;
      s_gf448_cswap(x2, x3, swap);
      s_gf448_cswap(z2, z3, swap);
      swap = k_t;

      s_gf448_add(a, x2, z2);       /* A  = x_2 + z_2       */
      s_gf448_sqr(aa, a);           /* AA = A^2             */
      s_gf448_sub(b, x2, z2);       /* B  = x_2 - z_2       */
      s_gf448_sqr(bb, b);           /* BB = B^2             */
      s_gf448_sub(e, aa, bb);       /* E  = AA - BB         */
      s_gf448_add(c, x3, z3);       /* C  = x_3 + z_3       */
      s_gf448_sub(d, x3, z3);       /* D  = x_3 - z_3       */
      s_gf448_mul(da, d, a);        /* DA = D * A           */
      s_gf448_mul(cb, c, b);        /* CB = C * B           */

      s_gf448_add(x3, da, cb);      /* x_3 = (DA + CB)^2    */
      s_gf448_sqr(x3, x3);

      s_gf448_sub(z3, da, cb);      /* z_3 = x_1*(DA-CB)^2  */
      s_gf448_sqr(z3, z3);
      s_gf448_mul(z3, x1, z3);

      s_gf448_mul(x2, aa, bb);      /* x_2 = AA * BB        */

      s_gf448_mul(t, a24, e);       /* z_2 = E*(AA + a24*E) */
      s_gf448_add(t, aa, t);
      s_gf448_mul(z2, e, t);
   }

   s_gf448_cswap(x2, x3, swap);
   s_gf448_cswap(z2, z3, swap);

   s_gf448_inv(t, z2);
   s_gf448_mul(x2, x2, t);

   s_gf448_encode(out, x2);

   zeromem(sk, sizeof(sk));
   return CRYPT_OK;
}

/* X448 scalar multiplication with base point u=5 */
static const unsigned char s_x448_basepoint[56] = {
   5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0
};

int ec448_scalarmult_base_internal(unsigned char *out, const unsigned char *scalar)
{
   ec448_scalarmult_internal(out, scalar, s_x448_basepoint);
   return CRYPT_OK;
}

#endif
