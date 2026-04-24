/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ed448_verify.c
  Verify an Ed448 signature, Steffen Jaeckel
*/

#ifdef LTC_CURVE448

static int s_ed448_verify(const  unsigned char *msg, unsigned long msglen,
                          const  unsigned char *sig, unsigned long siglen,
                          const  unsigned char *ctx, unsigned long ctxlen,
                                           int *stat,
                          const curve448_key *public_key)
{
   unsigned char *m;
   unsigned long long mlen;
   int err;

   LTC_ARGCHK(msg        != NULL);
   LTC_ARGCHK(sig        != NULL);
   LTC_ARGCHK(stat       != NULL);
   LTC_ARGCHK(public_key != NULL);

   *stat = 0;

   if (siglen != 114uL) return CRYPT_INVALID_ARG;
   if (public_key->pka != LTC_PKA_ED448) return CRYPT_PK_INVALID_TYPE;

   mlen = msglen + siglen;
   if ((mlen < msglen) || (mlen < siglen)) return CRYPT_OVERFLOW;

   m = XMALLOC((unsigned long)mlen);
   if (m == NULL) return CRYPT_MEM;

   XMEMCPY(m, sig, siglen);
   XMEMCPY(m + siglen, msg, msglen);

   err = ec448_verify_internal(stat,
                                m, &mlen,
                                m, mlen,
                                ctx, ctxlen,
                                public_key->pub);

#ifdef LTC_CLEAN_STACK
   zeromem(m, msglen + siglen);
#endif
   XFREE(m);

   return err;
}

/**
   Verify an Ed448ctx signature.
   @param msg             [in] The data to be verified
   @param msglen          [in] The size of the data to be verified
   @param sig             [in] The signature to be verified
   @param siglen          [in] The size of the signature to be verified
   @param ctx             [in] The context
   @param ctxlen          [in] The size of the context
   @param stat            [out] The result of the signature verification, 1==valid, 0==invalid
   @param public_key      [in] The public Ed448 key in the pair
   @return CRYPT_OK if successful
*/
int ed448ctx_verify(const  unsigned char *msg, unsigned long msglen,
                    const  unsigned char *sig, unsigned long siglen,
                    const  unsigned char *ctx, unsigned long ctxlen,
                                     int *stat,
                    const curve448_key *public_key)
{
   int err;
   unsigned char ctx_prefix[266];
   unsigned long ctx_prefix_size = sizeof(ctx_prefix);

   LTC_ARGCHK(ctx != NULL);

   if ((err = ec448_crypto_ctx(ctx_prefix, &ctx_prefix_size, 0, ctx, ctxlen)) != CRYPT_OK)
      return err;

   return s_ed448_verify(msg, msglen, sig, siglen, ctx_prefix, ctx_prefix_size, stat, public_key);
}

/**
   Verify an Ed448ph signature.
   @param msg             [in] The data to be verified
   @param msglen          [in] The size of the data to be verified
   @param sig             [in] The signature to be verified
   @param siglen          [in] The size of the signature to be verified
   @param ctx             [in] The context
   @param ctxlen          [in] The size of the context
   @param stat            [out] The result of the signature verification, 1==valid, 0==invalid
   @param public_key      [in] The public Ed448 key in the pair
   @return CRYPT_OK if successful
*/
int ed448ph_verify(const  unsigned char *msg, unsigned long msglen,
                   const  unsigned char *sig, unsigned long siglen,
                   const  unsigned char *ctx, unsigned long ctxlen,
                                    int *stat,
                   const curve448_key *public_key)
{
   int err;
   unsigned char msg_hash[64];
   unsigned char ctx_prefix[266];
   unsigned long ctx_prefix_size = sizeof(ctx_prefix);

   if ((err = ec448_crypto_ctx(ctx_prefix, &ctx_prefix_size, 1, ctx, ctxlen)) != CRYPT_OK)
      return err;

   if ((err = ec448_prehash_internal(msg_hash, msg, msglen)) != CRYPT_OK)
      return err;

   return s_ed448_verify(msg_hash, sizeof(msg_hash), sig, siglen, ctx_prefix, ctx_prefix_size, stat, public_key);
}

/**
   Verify an Ed448 signature (pure mode).
   @param msg             [in] The data to be verified
   @param msglen          [in] The size of the data to be verified
   @param sig             [in] The signature to be verified
   @param siglen          [in] The size of the signature to be verified
   @param stat            [out] The result of the signature verification, 1==valid, 0==invalid
   @param public_key      [in] The public Ed448 key in the pair
   @return CRYPT_OK if successful
*/
int ed448_verify(const  unsigned char *msg, unsigned long msglen,
                 const  unsigned char *sig, unsigned long siglen,
                                  int *stat,
                 const curve448_key *public_key)
{
   int err;
   unsigned char ctx_prefix[266];
   unsigned long ctx_prefix_size = sizeof(ctx_prefix);

   /* Pure Ed448 still uses DOM4 with flag=0 and empty context */
   if ((err = ec448_crypto_ctx(ctx_prefix, &ctx_prefix_size, 0, NULL, 0)) != CRYPT_OK)
      return err;

   return s_ed448_verify(msg, msglen, sig, siglen, ctx_prefix, ctx_prefix_size, stat, public_key);
}

#endif
