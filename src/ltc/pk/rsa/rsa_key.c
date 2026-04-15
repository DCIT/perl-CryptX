/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file rsa_key.c
  Free an RSA key, Tom St Denis
  Basic operations on an RSA key, Steffen Jaeckel
*/

#ifdef LTC_MRSA
static void s_mpi_shrink_multi(void **a, ...)
{
   void **cur;
   unsigned n;
   int err;
   va_list args;
   void *tmp[10] = { 0 };
   void **arg[10] = { 0 };

   /* We re-allocate in the order that we received the varargs */
   n = 0;
   err = CRYPT_ERROR;
   cur = a;
   va_start(args, a);
   while (cur != NULL) {
      if (n >= LTC_ARRAY_SIZE(tmp)) {
         goto out;
      }
      if (*cur != NULL) {
         arg[n] = cur;
         if ((err = ltc_mp_init_copy(&tmp[n], *arg[n])) != CRYPT_OK) {
            goto out;
         }
         n++;
      }
      cur = va_arg(args, void**);
   }
   va_end(args);

   /* but we clear the old values in the reverse order */
   while (n != 0 && arg[--n] != NULL) {
      ltc_mp_clear(*arg[n]);
      *arg[n] = tmp[n];
   }
out:
   va_end(args);
   /* clean-up after an error
    * or after this was called with too many args
    */
   if ((err != CRYPT_OK) ||
         (n >= LTC_ARRAY_SIZE(tmp))) {
      for (n = 0; n < LTC_ARRAY_SIZE(tmp); ++n) {
         if (tmp[n] != NULL) {
            ltc_mp_clear(tmp[n]);
         }
      }
   }
}

/**
  This shrinks the allocated memory of a RSA key

     It will use up some more memory temporarily,
     but then it will free-up the entire sequence that
     was once allocated when the key was created/populated.

     This only works with libtommath >= 1.2.0 in earlier versions
     it has the inverse effect due to the way it worked internally.
     Also works for GNU MP, tomsfastmath naturally shows no effect.

  @param key   The RSA key to shrink
*/
void rsa_shrink_key(rsa_key *key)
{
   LTC_ARGCHKVD(key != NULL);
   s_mpi_shrink_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, NULL);
}

/**
  Init an RSA key
  @param key   The RSA key to initialize
  @return CRYPT_OK if successful
*/
int rsa_init(rsa_key *key)
{
   LTC_ARGCHK(key != NULL);
   key->pss_oaep = 0;
   XMEMSET(&key->params, 0, sizeof(key->params));
   return ltc_mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, LTC_NULL);
}

/**
  Free an RSA key from memory
  @param key   The RSA key to free
*/
void rsa_free(rsa_key *key)
{
   LTC_ARGCHKVD(key != NULL);
   ltc_mp_cleanup_multi(&key->q, &key->p, &key->qP, &key->dP, &key->dQ, &key->N, &key->d, &key->e, LTC_NULL);
   key->pss_oaep = 0;
   XMEMSET(&key->params, 0, sizeof(key->params));
}

static LTC_INLINE int s_rsa_key_valid_rsa_params(ltc_rsa_op_checked *check)
{
   const ltc_rsa_parameters *key_params;
   /* This is called from PKCS#1 de-/encoder code, so we can't check the key */
   if (check->key == NULL) {
      return CRYPT_OK;
   }
   key_params = &check->key->params;
   /* Key has no PSS/OAEP constraints */
   if (!check->key->pss_oaep) {
      return CRYPT_OK;
   }
   /* Key is constrained - operation must use matching PSS/OAEP params */
   if (check->params->padding != LTC_PKCS_1_PSS
         && check->params->padding != LTC_PKCS_1_OAEP) {
      return CRYPT_PK_TYPE_MISMATCH;
   }
   if (key_params->hash_idx != check->hash_alg) {
      return CRYPT_INVALID_HASH;
   }
   if (key_params->mgf1_hash_idx != check->mgf1_hash_alg) {
      return CRYPT_INVALID_HASH;
   }
   return CRYPT_OK;
}

static LTC_INLINE int s_rsa_key_set_hash_algs(ltc_rsa_op_checked *check)
{
   ltc_rsa_op_parameters *params = check->params;
   if (hash_is_valid(params->params.hash_idx) != CRYPT_OK) {
      return CRYPT_INVALID_HASH;
   }
   check->hash_alg = params->params.hash_idx;
   if (params->params.mgf1_hash_idx == -1) {
      if (params->padding != LTC_PKCS_1_PSS && params->padding != LTC_PKCS_1_OAEP)
         return CRYPT_OK;
   } else if (hash_is_valid(params->params.mgf1_hash_idx) == CRYPT_OK) {
      check->mgf1_hash_alg = params->params.mgf1_hash_idx;
      return CRYPT_OK;
   }
   return CRYPT_INVALID_HASH;
}

static LTC_INLINE int s_rsa_key_valid_sign(ltc_rsa_op_checked *check)
{
   ltc_rsa_op_parameters *params = check->params;
   if ((params->padding != LTC_PKCS_1_V1_5)
         && (params->padding != LTC_PKCS_1_PSS)
         && (params->padding != LTC_PKCS_1_V1_5_NA1)) {
      return CRYPT_PK_INVALID_PADDING;
   }

   if (params->padding != LTC_PKCS_1_V1_5_NA1) {
      int err = s_rsa_key_set_hash_algs(check);
      if (err != CRYPT_OK) {
         return err;
      }
   }
   if (params->padding == LTC_PKCS_1_V1_5) {
      /* not all hashes have OIDs... so sad */
      if (check->hash_alg == -1
            || hash_descriptor[check->hash_alg].OIDlen == 0) {
         return CRYPT_INVALID_ARG;
      }
   }
   return s_rsa_key_valid_rsa_params(check);
}

static LTC_INLINE int s_rsa_key_valid_crypt(ltc_rsa_op_checked *check)
{
   ltc_rsa_op_parameters *params = check->params;
   if ((params->padding != LTC_PKCS_1_V1_5) &&
       (params->padding != LTC_PKCS_1_OAEP)) {
     return CRYPT_PK_INVALID_PADDING;
   }

   if (params->padding == LTC_PKCS_1_OAEP) {
      int err = s_rsa_key_set_hash_algs(check);
      if (err != CRYPT_OK) {
         return err;
      }
   }
   return s_rsa_key_valid_rsa_params(check);
}

static LTC_INLINE int s_rsa_check_prng(ltc_rsa_op op, ltc_rsa_op_parameters *params)
{
   /* Only PSS signing needs a PRNG, v1.5 signing is deterministic.
    * All encryption needs a PRNG (OAEP seed, v1.5 EME random padding). */
   if ((op & LTC_RSA_OP_SIGN) == LTC_RSA_OP_SIGN
         && params->padding != LTC_PKCS_1_PSS)
      return CRYPT_OK;
   if (params->prng == NULL)
      return CRYPT_INVALID_PRNG;
   /* valid prng ? */
   return prng_is_valid(params->wprng);
}

int rsa_key_valid_op(ltc_rsa_op op, ltc_rsa_op_checked *check)
{
   int err;
   check->hash_alg = check->mgf1_hash_alg = -1;
   LTC_ARGCHK(check->params != NULL);
   if ((op & LTC_RSA_OP_PKCS1) != LTC_RSA_OP_PKCS1) {
      /* PKCS#1 ops don't need an RSA key */
      LTC_ARGCHK(check->key    != NULL);
   }
   if ((op & LTC_RSA_OP_SEND) == LTC_RSA_OP_SEND) {
      if ((err = s_rsa_check_prng(op, check->params)) != CRYPT_OK) {
         return err;
      }
   }
   switch (op) {
      case LTC_RSA_ENCRYPT:
      case LTC_RSA_DECRYPT:
      case LTC_PKCS1_ENCRYPT:
      case LTC_PKCS1_DECRYPT:
         return s_rsa_key_valid_crypt(check);
      case LTC_RSA_SIGN:
      case LTC_RSA_VERIFY:
      case LTC_PKCS1_SIGN:
      case LTC_PKCS1_VERIFY:
         return s_rsa_key_valid_sign(check);
   }
   return CRYPT_ERROR;
}

int rsa_params_equal(const ltc_rsa_parameters *a, const ltc_rsa_parameters *b)
{
   if (a->saltlen != b->saltlen)
      return 0;
   if (a->hash_idx != b->hash_idx)
      return 0;
   if (a->mgf1_hash_idx != b->mgf1_hash_idx)
      return 0;
   return 1;
}

#endif
