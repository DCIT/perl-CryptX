/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file crypt_register_cipher.c
  Register a cipher, Tom St Denis
*/

/**
   Register a cipher with the descriptor table
   @param cipher   The cipher you wish to register
   @return value >= 0 if successfully added (or already present), -1 if unsuccessful
*/
int register_cipher(const struct ltc_cipher_descriptor *cipher)
{
   int x, blank = -1;

   LTC_ARGCHK(cipher != NULL);

   if (cipher->name == NULL)
      return -1;

   /* is it already registered? */
   LTC_MUTEX_LOCK(&ltc_cipher_mutex);
   for (x = 0; x < TAB_SIZE; x++) {
       if (cipher_descriptor[x].name != NULL && cipher_descriptor[x].ID == cipher->ID) {
          LTC_MUTEX_UNLOCK(&ltc_cipher_mutex);
          return x;
       }
       if (cipher_descriptor[x].name == NULL && blank == -1) {
          blank = x;
       }
   }

   /* find a blank spot */
   if (blank != -1) {
       XMEMCPY(&cipher_descriptor[blank], cipher, sizeof(struct ltc_cipher_descriptor));
   }

   /* no spot */
   LTC_MUTEX_UNLOCK(&ltc_cipher_mutex);
   return blank;
}
