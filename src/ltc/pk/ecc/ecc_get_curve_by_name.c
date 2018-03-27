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

/* case-insensitive match + ignore '-', '_', ' ' */
static int _name_match(const char *left, const char *right)
{
   char lc_r, lc_l;

   while ((*left != '\0') && (*right != '\0')) {
      while ((*left  == ' ') || (*left  == '-') || (*left  == '_')) left++;
      while ((*right == ' ') || (*right == '-') || (*right == '_')) right++;
      if (*left == '\0' || *right == '\0') break;
      lc_r = *right;
      lc_l = *left;
      if ((lc_r >= 'A') && (lc_r <= 'Z')) lc_r += 32;
      if ((lc_l >= 'A') && (lc_l <= 'Z')) lc_l += 32;
      if (lc_l != lc_r) return 0;
      left++;
      right++;
   }

   if ((*left == '\0') && (*right == '\0'))
      return 1;
   else
      return 0;
}

int ecc_get_curve_by_name(const char *name, const ltc_ecc_curve **cu)
{
   int i, j;

   LTC_ARGCHK(cu != NULL);
   LTC_ARGCHK(name != NULL);

   *cu = NULL;

   for (i = 0; ltc_ecc_curves[i].prime != NULL; i++) {
      for (j = 0; ltc_ecc_curves[i].names[j] != NULL; j++) {
         if (_name_match(ltc_ecc_curves[i].names[j], name)) {
            *cu = &ltc_ecc_curves[i];
            return CRYPT_OK;
         }
      }
   }

   return CRYPT_INVALID_ARG; /* not found */
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
