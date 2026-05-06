/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pqc_algname_match.c
  Shared name-matching helper for PQC algorithm lookup tables.
*/

#if defined(LTC_MLKEM) || defined(LTC_MLDSA) || defined(LTC_SLHDSA)

/**
   Compare two algorithm-name strings.

   Matching is case-insensitive (ASCII) and ignores '-' and '_' on both
   sides, so e.g. "ML-KEM-768", "ml_kem_768", and "MLKEM768" all match.
   Used for ML-KEM / ML-DSA / SLH-DSA name lookup; safe to use against
   dotted-decimal OIDs since those contain no separators or letters.
   @param left   First NUL-terminated string
   @param right  Second NUL-terminated string
   @return 1 if the strings match under the relaxed rules, 0 otherwise
*/
int ltc_pqc_algname_match(const char *left, const char *right)
{
   char lc_r, lc_l;

   if (left == NULL || right == NULL) return 0;

   while ((*left != '\0') && (*right != '\0')) {
      while ((*left  == '-') || (*left  == '_')) left++;
      while ((*right == '-') || (*right == '_')) right++;
      if (*left == '\0' || *right == '\0') break;
      lc_r = *right;
      lc_l = *left;
      if ((lc_r >= 'A') && (lc_r <= 'Z')) lc_r += 32;
      if ((lc_l >= 'A') && (lc_l <= 'Z')) lc_l += 32;
      if (lc_l != lc_r) return 0;
      left++;
      right++;
   }

   if ((*left == '\0') && (*right == '\0')) return 1;
   return 0;
}

#endif
