/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ed448_sign.c
  Create an Ed448 signature, Steffen Jaeckel
*/

#ifdef LTC_CURVE448

static int s_ed448_sign(const unsigned char  *msg, unsigned long  msglen,
                              unsigned char  *sig, unsigned long *siglen,
                        const unsigned char  *ctx, unsigned long  ctxlen,
                        const curve448_key *private_key)
{
   unsigned char *s;
   unsigned long long smlen;
   int err;

   LTC_ARGCHK(msg         != NULL);
   LTC_ARGCHK(sig         != NULL);
   LTC_ARGCHK(siglen      != NULL);
   LTC_ARGCHK(private_key != NULL);

   if (private_key->pka != LTC_PKA_ED448) return CRYPT_PK_INVALID_TYPE;
   if (private_key->type != PK_PRIVATE) return CRYPT_PK_INVALID_TYPE;

   if (*siglen < 114uL) {
      *siglen = 114uL;
      return CRYPT_BUFFER_OVERFLOW;
   }

   smlen = msglen + 114;
   s = XMALLOC((unsigned long)smlen);
   if (s == NULL) return CRYPT_MEM;

   err = ec448_sign_internal(s, &smlen,
                           msg, msglen,
                           private_key->priv, private_key->pub,
                           ctx, ctxlen);

   XMEMCPY(sig, s, 114uL);
   *siglen = 114uL;

#ifdef LTC_CLEAN_STACK
   zeromem(s, (unsigned long)smlen);
#endif
   XFREE(s);

   return err;
}

/**
   Create an Ed448ctx signature.
   @param msg             The data to be signed
   @param msglen          [in] The size of the data to be signed
   @param sig             [out] The destination of the signature
   @param siglen          [in/out] The max size and resulting size of the signature
   @param ctx             [in] The context
   @param ctxlen          [in] The size of the context
   @param private_key     The private Ed448 key in the pair
   @return CRYPT_OK if successful
*/
int ed448ctx_sign(const  unsigned char *msg, unsigned long  msglen,
                         unsigned char *sig, unsigned long *siglen,
                  const  unsigned char *ctx, unsigned long  ctxlen,
                  const curve448_key *private_key)
{
   int err;
   unsigned char ctx_prefix[266];
   unsigned long ctx_prefix_size = sizeof(ctx_prefix);

   LTC_ARGCHK(ctx != NULL);

   if ((err = ec448_crypto_ctx(ctx_prefix, &ctx_prefix_size, 0, ctx, ctxlen)) != CRYPT_OK)
      return err;

   return s_ed448_sign(msg, msglen, sig, siglen, ctx_prefix, ctx_prefix_size, private_key);
}

/**
   Create an Ed448ph signature.
   @param msg             The data to be signed
   @param msglen          [in] The size of the data to be signed
   @param sig             [out] The destination of the signature
   @param siglen          [in/out] The max size and resulting size of the signature
   @param ctx             [in] The context
   @param ctxlen          [in] The size of the context
   @param private_key     The private Ed448 key in the pair
   @return CRYPT_OK if successful
*/
int ed448ph_sign(const  unsigned char *msg, unsigned long  msglen,
                        unsigned char *sig, unsigned long *siglen,
                 const  unsigned char *ctx, unsigned long  ctxlen,
                 const curve448_key *private_key)
{
   int err;
   unsigned char msg_hash[64];
   unsigned char ctx_prefix[266];
   unsigned long ctx_prefix_size = sizeof(ctx_prefix);

   if ((err = ec448_crypto_ctx(ctx_prefix, &ctx_prefix_size, 1, ctx, ctxlen)) != CRYPT_OK)
      return err;

   if ((err = ec448_prehash_internal(msg_hash, msg, msglen)) != CRYPT_OK)
      return err;

   return s_ed448_sign(msg_hash, sizeof(msg_hash), sig, siglen, ctx_prefix, ctx_prefix_size, private_key);
}

/**
   Create an Ed448 signature (pure mode).
   @param msg             The data to be signed
   @param msglen          [in] The size of the data to be signed
   @param sig             [out] The destination of the signature
   @param siglen          [in/out] The max size and resulting size of the signature
   @param private_key     The private Ed448 key in the pair
   @return CRYPT_OK if successful
*/
int ed448_sign(const  unsigned char *msg, unsigned long msglen,
                      unsigned char *sig, unsigned long *siglen,
               const curve448_key *private_key)
{
   int err;
   unsigned char ctx_prefix[266];
   unsigned long ctx_prefix_size = sizeof(ctx_prefix);

   /* Pure Ed448 still uses DOM4 with flag=0 and empty context */
   if ((err = ec448_crypto_ctx(ctx_prefix, &ctx_prefix_size, 0, NULL, 0)) != CRYPT_OK)
      return err;

   return s_ed448_sign(msg, msglen, sig, siglen, ctx_prefix, ctx_prefix_size, private_key);
}

#endif
