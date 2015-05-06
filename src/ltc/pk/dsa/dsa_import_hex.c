/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"

/**
   @file dsa_import_hex.c
   DSA implementation, import a DSA key
*/

#ifdef LTC_MDSA

int dsa_import_hex(char *p, char *q, char *g, char *x, char *y, dsa_key *key)
{
   int           err;

   LTC_ARGCHK(p != NULL);
   LTC_ARGCHK(q != NULL);
   LTC_ARGCHK(g != NULL);
   LTC_ARGCHK(y != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* init key */
   err = mp_init_multi(&key->p, &key->g, &key->q, &key->x, &key->y, NULL);
   if (err != CRYPT_OK) return err;
   
   if ((err = mp_read_radix(key->p , p , 16)) != CRYPT_OK) { goto LBL_ERR; }
   if ((err = mp_read_radix(key->q , q , 16)) != CRYPT_OK) { goto LBL_ERR; }
   if ((err = mp_read_radix(key->g , g , 16)) != CRYPT_OK) { goto LBL_ERR; }
   if ((err = mp_read_radix(key->g , y , 16)) != CRYPT_OK) { goto LBL_ERR; }
   if (x && strlen(x) > 0) {
     key->type = PK_PRIVATE;
   }
   else {
     key->type = PK_PUBLIC;
   }
   return CRYPT_OK;

LBL_ERR:
   mp_clear_multi(key->p, key->g, key->q, key->x, key->y, NULL);
   return err;
}

#endif
