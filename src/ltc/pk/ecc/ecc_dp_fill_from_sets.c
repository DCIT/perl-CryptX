/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 */

#include "tomcrypt.h"

#ifdef LTC_MECC

static int hexstrcmp(const char *hexa, const char *hexb)
{
  #define MY_TOLOWER(a) ((((a)>='A')&&((a)<='Z')) ? ((a)|0x60) : (a))
  /* ignore leading zeroes */
  while(*hexa == '0') hexa++;
  while(*hexb == '0') hexb++;
  /* compare: case insensitive, hexadecimal chars only */
  while (*hexa && *hexb) {
    if ( (*hexa < '0' || *hexa > '9') &&
         (*hexa < 'a' || *hexa > 'f') &&
         (*hexa < 'A' || *hexa > 'F') ) return 1;
    if ( (*hexb < '0' || *hexb > '9') &&
         (*hexb < 'a' || *hexb > 'f') &&
         (*hexb < 'A' || *hexb > 'F') ) return 1;
    if (MY_TOLOWER(*hexa) != MY_TOLOWER(*hexb)) return 1;
    hexa++;
    hexb++;
  }
  if (*hexa == '\0' && *hexb == '\0') return 0; /* success - match */
  return 1;
}

/* search known curve by curve parameters and fill in missing parameters into dp
 * we assume every parameter has the same case (usually uppercase) and no leading zeros
 */
int ecc_dp_fill_from_sets(ltc_ecc_set_type *dp)
{
  ltc_ecc_set_type params;
  int x;

  if (!dp)                return CRYPT_INVALID_ARG;
  if (dp->oid.OIDlen > 0) return CRYPT_OK;
  if (!dp->prime || !dp->A || !dp->B || !dp->order || !dp->Gx || !dp->Gy || dp->cofactor == 0) return CRYPT_INVALID_ARG;

  for (x = 0; ltc_ecc_sets[x].size != 0; x++) {
    if (hexstrcmp(ltc_ecc_sets[x].prime, dp->prime) == 0 &&
        hexstrcmp(ltc_ecc_sets[x].A,     dp->A)     == 0 &&
        hexstrcmp(ltc_ecc_sets[x].B,     dp->B)     == 0 &&
        hexstrcmp(ltc_ecc_sets[x].order, dp->order) == 0 &&
        hexstrcmp(ltc_ecc_sets[x].Gx,    dp->Gx)    == 0 &&
        hexstrcmp(ltc_ecc_sets[x].Gy,    dp->Gy)    == 0 &&
        ltc_ecc_sets[x].cofactor == dp->cofactor) {

      params = ltc_ecc_sets[x];

      /* copy oid */
      dp->oid.OIDlen = params.oid.OIDlen;
      XMEMCPY(dp->oid.OID, params.oid.OID, dp->oid.OIDlen * sizeof(dp->oid.OID[0]));

      /* copy name */
      if (dp->name != NULL) XFREE(dp->name);
      if ((dp->name = XMALLOC(1+strlen(params.name))) == NULL) return CRYPT_MEM;
      strcpy(dp->name, params.name);

      return CRYPT_OK;
    }
  }

  return CRYPT_INVALID_ARG;
}

#endif
