/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file crypt_register_prng.c
  Register a PRNG, Tom St Denis
*/

/**
   Register a PRNG with the descriptor table
   @param prng   The PRNG you wish to register
   @return value >= 0 if successfully added (or already present), -1 if unsuccessful
*/
int register_prng(const struct ltc_prng_descriptor *prng)
{
   int x, blank = -1;

   LTC_ARGCHK(prng != NULL);

   if (prng->name == NULL)
      return -1;

   /* is it already registered? */
   LTC_MUTEX_LOCK(&ltc_prng_mutex);
   for (x = 0; x < TAB_SIZE; x++) {
       if (XMEMCMP(&prng_descriptor[x], prng, sizeof(struct ltc_prng_descriptor)) == 0) {
          LTC_MUTEX_UNLOCK(&ltc_prng_mutex);
          return x;
       }
       if (prng_descriptor[x].name == NULL && blank == -1) {
          blank = x;
       }
   }

   /* find a blank spot */
   if (blank != -1) {
       XMEMCPY(&prng_descriptor[blank], prng, sizeof(struct ltc_prng_descriptor));
   }

   /* no spot */
   LTC_MUTEX_UNLOCK(&ltc_prng_mutex);
   return blank;
}
