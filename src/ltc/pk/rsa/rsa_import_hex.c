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
  @file rsa_import_hex.c
  Import a PKCS RSA key
*/

#ifdef LTC_MRSA

int rsa_import_hex(char *N, char *e, char *d, char *p, char *q, char *dP, char *dQ, char *qP, rsa_key *key)
{
   int err;

   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(N           != NULL);
   LTC_ARGCHK(e           != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, NULL);
   if (err != CRYPT_OK) return err;

   if ((err = mp_read_radix(key->N , N , 16)) != CRYPT_OK)   { goto LBL_ERR; }
   if ((err = mp_read_radix(key->e , e , 16)) != CRYPT_OK)   { goto LBL_ERR; }
   if (d && p && q && dP && dQ && qP && strlen(d)>0 && strlen(p)>0 && 
       strlen(q)>0 && strlen(dP)>0 && strlen(dQ)>0 && strlen(qP)>0) {
     if ((err = mp_read_radix(key->d , d , 16)) != CRYPT_OK) { goto LBL_ERR; }
     if ((err = mp_read_radix(key->p , p , 16)) != CRYPT_OK) { goto LBL_ERR; }
     if ((err = mp_read_radix(key->q , q , 16)) != CRYPT_OK) { goto LBL_ERR; }
     if ((err = mp_read_radix(key->dP, dP, 16)) != CRYPT_OK) { goto LBL_ERR; }
     if ((err = mp_read_radix(key->dQ, dQ, 16)) != CRYPT_OK) { goto LBL_ERR; }
     if ((err = mp_read_radix(key->qP, qP, 16)) != CRYPT_OK) { goto LBL_ERR; }
     key->type = PK_PRIVATE;
   }
   else {
     key->type = PK_PUBLIC;
   }
   return CRYPT_OK;

LBL_ERR:
   mp_clear_multi(key->d,  key->e, key->N, key->dQ, key->dP, key->qP, key->p, key->q, NULL);
   return err;
}

#endif /* LTC_MRSA */
