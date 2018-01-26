/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_MECC

int ecc_get_set_by_name(const char* name, const ltc_ecc_set_type** dp)
{
   int i;

   LTC_ARGCHK(dp != NULL);
   LTC_ARGCHK(name != NULL);

   *dp = NULL;

   for (i = 0; ltc_ecc_sets[i].name != NULL; i++) {
      if (XSTRCMP(ltc_ecc_sets[i].name, name) == 0) break;
   }

   if (ltc_ecc_sets[i].name == NULL) {
      /* not found */
      return CRYPT_INVALID_ARG;
   }

   *dp = &ltc_ecc_sets[i];
   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
