/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file pmac_ntz.c
   PMAC implementation, internal function, by Tom St Denis
*/

#ifdef LTC_PMAC

/**
  Internal PMAC function
*/
int pmac_ntz(unsigned long x)
{
#if defined(LTC_HAVE_CTZL_BUILTIN)
   if (x == 0)
      return sizeof(unsigned long) * CHAR_BIT;
   return __builtin_ctzl(x);
#else
   int c;
   x &= 0xFFFFFFFFUL;
   c = 0;
   while ((x & 1) == 0) {
      ++c;
      x >>= 1;
   }
   return c;
#endif
}

#endif
