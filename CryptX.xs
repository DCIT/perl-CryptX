#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define NEED_sv_2pvbyte_GLOBAL
#define NEED_sv_2pv_flags_GLOBAL
#define NEED_newRV_noinc_GLOBAL
#include "ppport.h"

#undef LTC_SOURCE
#include "tomcrypt.h"
#include "tommath.h"

typedef adler32_state *Crypt__Checksum__Adler32;
typedef crc32_state   *Crypt__Checksum__CRC32;

typedef struct cipher_struct {          /* used by Crypt::Cipher */
  symmetric_key skey;
  int id;
  struct ltc_cipher_descriptor *desc;
} *Crypt__Cipher;

typedef struct digest_struct {          /* used by Crypt::Digest */
  hash_state state;
  int id;
  struct ltc_hash_descriptor *desc;
} *Crypt__Digest;

typedef struct ccm_struct {             /* used by Crypt::AuthEnc::CCM */
  int id;
} *Crypt__AuthEnc__CCM;

typedef struct eax_struct {             /* used by Crypt::AuthEnc::EAX */
  eax_state state;
  int id;
} *Crypt__AuthEnc__EAX;

typedef struct gcm_struct {             /* used by Crypt::AuthEnc::GCM */
  gcm_state state;
  int id;
} *Crypt__AuthEnc__GCM;

typedef struct ocb_struct {             /* used by Crypt::AuthEnc::OCB */
  ocb3_state state;
  int id;
} *Crypt__AuthEnc__OCB;

typedef struct f9_struct {              /* used by Crypt::Mac::F9 */
  f9_state state;
  int id;
} *Crypt__Mac__F9;

typedef struct hmac_struct {            /* used by Crypt::Mac::HMAC */
  hmac_state state;
  int id;
} *Crypt__Mac__HMAC;

typedef struct omac_struct {            /* used by Crypt::Mac::OMAC */
  omac_state state;
  int id;
} *Crypt__Mac__OMAC;

typedef struct pelican_struct {         /* used by Crypt::Mac::Pelican */
  pelican_state state;
  int id;
} *Crypt__Mac__Pelican;

typedef struct pmac_struct {            /* used by Crypt::Mac::PMAC */
  pmac_state state;
  int id;
} *Crypt__Mac__PMAC;

typedef struct xcbc_struct {            /* used by Crypt::Mac::XCBC */
  xcbc_state state;
  int id;
} *Crypt__Mac__XCBC;

typedef struct cbc_struct {             /* used by Crypt::Mode::CBC */
  int cipher_id, cipher_rounds;
  symmetric_CBC state;
  unsigned char pad[MAXBLOCKSIZE];
  int padlen;
  int padding_mode;
  int direction;
  int id;
} *Crypt__Mode__CBC;

typedef struct ecb_struct {             /* used by Crypt::Mode::ECB */
  int cipher_id, cipher_rounds;
  symmetric_ECB state;
  unsigned char pad[MAXBLOCKSIZE];
  int padlen;
  int padding_mode;
  int direction;
  int id;
} *Crypt__Mode__ECB;

typedef struct cfb_struct {             /* used by Crypt::Mode::CFB */
  int cipher_id, cipher_rounds;
  symmetric_CFB state;
  int direction;
  int id;
} *Crypt__Mode__CFB;

typedef struct ctr_struct {             /* used by Crypt::Mode::CTR */
  int cipher_id, cipher_rounds;
  int ctr_mode_param;
  symmetric_CTR state;
  int direction;
  int id;
} *Crypt__Mode__CTR;

typedef struct f8_struct {              /* used by Crypt::Mode::F8 */
  int cipher_id, cipher_rounds;
  symmetric_F8 state;
  int direction;
  int id;
} *Crypt__Mode__F8;

typedef struct lrw_struct {             /* used by Crypt::Mode::LRW */
  int cipher_id, cipher_rounds;
  symmetric_LRW state;
  int direction;
  int id;
} *Crypt__Mode__LRW;

typedef struct ofb_struct {             /* used by Crypt::Mode::OFB */
  int cipher_id, cipher_rounds;
  symmetric_OFB state;
  int direction;
  int id;
} *Crypt__Mode__OFB;

typedef struct xts_struct {             /* used by Crypt::Mode::XTS */
  int cipher_id, cipher_rounds;
  symmetric_xts state;
  int direction;
  int id;
} *Crypt__Mode__XTS;

typedef struct prng_struct {            /* used by Crypt::PRNG */
  prng_state state;
  struct ltc_prng_descriptor *desc;
  IV last_pid;
  int id;
} *Crypt__PRNG;

typedef struct rsa_struct {             /* used by Crypt::PK::RSA */
  prng_state yarrow_prng_state;
  int yarrow_prng_index;
  rsa_key key;
  int id;
} *Crypt__PK__RSA;

typedef struct dsa_struct {             /* used by Crypt::PK::DSA */
  prng_state yarrow_prng_state;
  int yarrow_prng_index;
  dsa_key key;
  int id;
} *Crypt__PK__DSA;

typedef struct dh_struct {              /* used by Crypt::PK::DH */
  prng_state yarrow_prng_state;
  int yarrow_prng_index;
  dh_key key;
  int id;
} *Crypt__PK__DH;

typedef struct ecc_struct {             /* used by Crypt::PK::ECC */
  prng_state yarrow_prng_state;
  int yarrow_prng_index;
  ecc_key key;
  ltc_ecc_set_type dp;
  int id;
} *Crypt__PK__ECC;

/* Math::BigInt::LTM related */
typedef mp_int * Math__BigInt__LTM;
STATIC SV * sv_from_mpi(mp_int *mpi) {
  SV *obj = newSV(0);
  sv_setref_pv(obj, "Math::BigInt::LTM", (void*)mpi);
  return obj;
}

ltc_ecc_set_type* _ecc_set_dp_from_SV(ltc_ecc_set_type *dp, SV *curve)
{
  HV *h;
  SV *param, **pref;
  SV **sv_cofactor, **sv_prime, **sv_A, **sv_B, **sv_order, **sv_Gx, **sv_Gy, **sv_oid;
  int err;
  char *ch_name;
  STRLEN l_name;

  if (SvPOK(curve)) {
    ch_name = SvPV(curve, l_name);
    if ((h = get_hv("Crypt::PK::ECC::curve", 0)) == NULL) croak("FATAL: generate_key_ex: no curve register");
    if ((pref = hv_fetch(h, ch_name, l_name, 0)) == NULL)  croak("FATAL: generate_key_ex: unknown curve/1 '%s'", ch_name);
    if (!SvOK(*pref)) croak("FATAL: generate_key_ex: unknown curve/2 '%s'", ch_name);
    param = *pref;
  }
  else if (SvROK(curve)) {
    param = curve;
  }
  else {
    croak("FATAL: curve has to be a string or a hashref");
  }

  if ((h = (HV*)(SvRV(param))) == NULL) croak("FATAL: ecparams: param is not valid hashref");

  if ((sv_prime    = hv_fetchs(h, "prime",    0)) == NULL) croak("FATAL: ecparams: missing param prime");
  if ((sv_A        = hv_fetchs(h, "A",        0)) == NULL) croak("FATAL: ecparams: missing param A");
  if ((sv_B        = hv_fetchs(h, "B",        0)) == NULL) croak("FATAL: ecparams: missing param B");
  if ((sv_order    = hv_fetchs(h, "order",    0)) == NULL) croak("FATAL: ecparams: missing param order");
  if ((sv_Gx       = hv_fetchs(h, "Gx",       0)) == NULL) croak("FATAL: ecparams: missing param Gx");
  if ((sv_Gy       = hv_fetchs(h, "Gy",       0)) == NULL) croak("FATAL: ecparams: missing param Gy");
  if ((sv_cofactor = hv_fetchs(h, "cofactor", 0)) == NULL) croak("FATAL: ecparams: missing param cofactor");

  if (!SvOK(*sv_prime   )) croak("FATAL: ecparams: undefined param prime");
  if (!SvOK(*sv_A       )) croak("FATAL: ecparams: undefined param A");
  if (!SvOK(*sv_B       )) croak("FATAL: ecparams: undefined param B");
  if (!SvOK(*sv_order   )) croak("FATAL: ecparams: undefined param order");
  if (!SvOK(*sv_Gx      )) croak("FATAL: ecparams: undefined param Gx");
  if (!SvOK(*sv_Gy      )) croak("FATAL: ecparams: undefined param Gy");
  if (!SvOK(*sv_cofactor)) croak("FATAL: ecparams: undefined param cofactor");

  err = ecc_dp_set( dp,
                    SvPV_nolen(*sv_prime),
                    SvPV_nolen(*sv_A),
                    SvPV_nolen(*sv_B),
                    SvPV_nolen(*sv_order),
                    SvPV_nolen(*sv_Gx),
                    SvPV_nolen(*sv_Gy),
                    (unsigned long)SvUV(*sv_cofactor),
                    NULL, /* we intentionally don't allow setting custom names */
                    NULL  /* we intentionally don't allow setting custom OIDs */
                  );
  return err == CRYPT_OK ? dp : NULL;
}

void _ecc_free_key(ecc_key *key, ltc_ecc_set_type *dp)
{
  if(dp) {
    ecc_dp_clear(dp);
  }
  if (key->type != -1) {
    ecc_free(key);
    key->type = -1;
    key->dp = NULL;
  }
}

MODULE = CryptX       PACKAGE = CryptX      PREFIX = CryptX_

BOOT:
    if(register_cipher(&blowfish_desc)==-1)    { croak("FATAL: cannot register_cipher blowfish"); }
    if(register_cipher(&rc5_desc)==-1)         { croak("FATAL: cannot register_cipher rc5"); }
    if(register_cipher(&rc6_desc)==-1)         { croak("FATAL: cannot register_cipher rc6"); }
    if(register_cipher(&rc2_desc)==-1)         { croak("FATAL: cannot register_cipher rc2"); }
    if(register_cipher(&saferp_desc)==-1)      { croak("FATAL: cannot register_cipher saferp"); }
    if(register_cipher(&safer_k64_desc)==-1)   { croak("FATAL: cannot register_cipher safer_k64"); }
    if(register_cipher(&safer_k128_desc)==-1)  { croak("FATAL: cannot register_cipher safer_k128"); }
    if(register_cipher(&safer_sk64_desc)==-1)  { croak("FATAL: cannot register_cipher safer_sk64"); }
    if(register_cipher(&safer_sk128_desc)==-1) { croak("FATAL: cannot register_cipher safer_sk128"); }
    if(register_cipher(&aes_desc)==-1)         { croak("FATAL: cannot register_cipher aes"); }
    if(register_cipher(&xtea_desc)==-1)        { croak("FATAL: cannot register_cipher xtea"); }
    if(register_cipher(&twofish_desc)==-1)     { croak("FATAL: cannot register_cipher twofish"); }
    if(register_cipher(&des_desc)==-1)         { croak("FATAL: cannot register_cipher des"); }
    if(register_cipher(&des3_desc)==-1)        { croak("FATAL: cannot register_cipher des3"); }
    if(register_cipher(&cast5_desc)==-1)       { croak("FATAL: cannot register_cipher cast5"); }
    if(register_cipher(&noekeon_desc)==-1)     { croak("FATAL: cannot register_cipher noekeon"); }
    if(register_cipher(&skipjack_desc)==-1)    { croak("FATAL: cannot register_cipher skipjack"); }
    if(register_cipher(&khazad_desc)==-1)      { croak("FATAL: cannot register_cipher khazad"); }
    if(register_cipher(&anubis_desc)==-1)      { croak("FATAL: cannot register_cipher anubis"); }
    if(register_cipher(&kseed_desc)==-1)       { croak("FATAL: cannot register_cipher kseed"); }
    if(register_cipher(&kasumi_desc)==-1)      { croak("FATAL: cannot register_cipher kasumi"); }
    if(register_cipher(&multi2_desc)==-1)      { croak("FATAL: cannot register_cipher multi2"); }
    if(register_cipher(&camellia_desc)==-1)    { croak("FATAL: cannot register_cipher camellia"); }
    /* --- */
    if(register_hash(&chc_desc)==-1)           { croak("FATAL: cannot register_hash chc_hash"); }
    if(register_hash(&md2_desc)==-1)           { croak("FATAL: cannot register_hash md2"); }
    if(register_hash(&md4_desc)==-1)           { croak("FATAL: cannot register_hash md4"); }
    if(register_hash(&md5_desc)==-1)           { croak("FATAL: cannot register_hash md5"); }
    if(register_hash(&rmd128_desc)==-1)        { croak("FATAL: cannot register_hash rmd128"); }
    if(register_hash(&rmd160_desc)==-1)        { croak("FATAL: cannot register_hash rmd160"); }
    if(register_hash(&rmd256_desc)==-1)        { croak("FATAL: cannot register_hash rmd256"); }
    if(register_hash(&rmd320_desc)==-1)        { croak("FATAL: cannot register_hash rmd320"); }
    if(register_hash(&sha1_desc)==-1)          { croak("FATAL: cannot register_hash sha1"); }
    if(register_hash(&sha224_desc)==-1)        { croak("FATAL: cannot register_hash sha224"); }
    if(register_hash(&sha256_desc)==-1)        { croak("FATAL: cannot register_hash sha256"); }
    if(register_hash(&sha384_desc)==-1)        { croak("FATAL: cannot register_hash sha384"); }
    if(register_hash(&sha512_desc)==-1)        { croak("FATAL: cannot register_hash sha512"); }
    if(register_hash(&sha512_224_desc)==-1)    { croak("FATAL: cannot register_hash sha512_224"); }
    if(register_hash(&sha512_256_desc)==-1)    { croak("FATAL: cannot register_hash sha512_256"); }
    if(register_hash(&tiger_desc)==-1)         { croak("FATAL: cannot register_hash tiger"); }
    if(register_hash(&whirlpool_desc)==-1)     { croak("FATAL: cannot register_hash whirlpool"); }
    /* --- */
    if(chc_register(find_cipher("aes"))==-1)   { croak("FATAL: chc_register failed"); }
    /* --- */
    if(register_prng(&fortuna_desc)==-1)       { croak("FATAL: cannot register_prng fortuna"); }
    if(register_prng(&rc4_desc)==-1)           { croak("FATAL: cannot register_prng rc4"); }
    if(register_prng(&sober128_desc)==-1)      { croak("FATAL: cannot register_prng sober128"); }
    if(register_prng(&yarrow_desc)==-1)        { croak("FATAL: cannot register_prng yarrow"); }
    /* --- */
#ifdef TFM_DESC
    ltc_mp = tfm_desc;
#else
    ltc_mp = ltm_desc;
#endif

SV *
CryptX__encode_base64url(SV * in)
    CODE:
    {
        STRLEN in_len;
        unsigned long out_len;
        unsigned char *out_data, *in_data;
        int rv;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        in_data = (unsigned char *) SvPVbyte(in, in_len);
        out_len = 4 * ((in_len + 2) / 3) + 1;
        Newz(0, out_data, out_len, unsigned char);
        if (!out_data) croak("FATAL: Newz failed [%ld]", out_len);
        rv = base64url_encode(in_data, (unsigned long)in_len, out_data, &out_len);
        RETVAL = (rv == CRYPT_OK) ? newSVpvn((char *)out_data, out_len) : newSVpvn(NULL, 0);
        Safefree(out_data);
    }
    OUTPUT:
        RETVAL

SV *
CryptX__decode_base64url(SV * in)
    CODE:
    {
        STRLEN in_len;
        unsigned long out_len;
        unsigned char *out_data, *in_data;
        int rv;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        in_data = (unsigned char *) SvPVbyte(in, in_len);
        out_len = in_len;
        Newz(0, out_data, out_len, unsigned char);
        if (!out_data) croak("FATAL: Newz failed [%ld]", out_len);
        rv = base64url_decode(in_data, (unsigned long)in_len, out_data, &out_len);
        RETVAL = (rv == CRYPT_OK) ? newSVpvn((char *)out_data, out_len) : newSVpvn(NULL, 0);
        Safefree(out_data);
    }
    OUTPUT:
        RETVAL

SV *
CryptX__encode_base64(SV * in)
    CODE:
    {
        STRLEN in_len;
        unsigned long out_len;
        unsigned char *out_data, *in_data;
        int rv;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        in_data = (unsigned char *) SvPVbyte(in, in_len);
        out_len = 4 * ((in_len + 2) / 3) + 1;
        Newz(0, out_data, out_len, unsigned char);
        if (!out_data) croak("FATAL: Newz failed [%ld]", out_len);
        rv = base64_encode(in_data, (unsigned long)in_len, out_data, &out_len);
        RETVAL = (rv == CRYPT_OK) ? newSVpvn((char *)out_data, out_len) : newSVpvn(NULL, 0);
        Safefree(out_data);
    }
    OUTPUT:
        RETVAL

SV *
CryptX__decode_base64(SV * in)
    CODE:
    {
        STRLEN in_len;
        unsigned long out_len;
        unsigned char *out_data, *in_data;
        int rv;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        in_data = (unsigned char *) SvPVbyte(in, in_len);
        out_len = in_len;
        Newz(0, out_data, out_len, unsigned char);
        if (!out_data) croak("FATAL: Newz failed [%ld]", out_len);
        rv = base64_decode(in_data, (unsigned long)in_len, out_data, &out_len);
        RETVAL = (rv == CRYPT_OK) ? newSVpvn((char *)out_data, out_len) : newSVpvn(NULL, 0);
        Safefree(out_data);
    }
    OUTPUT:
        RETVAL

###############################################################################

INCLUDE: inc/CryptX_Digest.xs.inc
INCLUDE: inc/CryptX_Cipher.xs.inc

INCLUDE: inc/CryptX_Checksum_Adler32.xs.inc
INCLUDE: inc/CryptX_Checksum_CRC32.xs.inc

INCLUDE: inc/CryptX_AuthEnc_EAX.xs.inc
INCLUDE: inc/CryptX_AuthEnc_GCM.xs.inc
INCLUDE: inc/CryptX_AuthEnc_OCB.xs.inc
INCLUDE: inc/CryptX_AuthEnc_CCM.xs.inc

INCLUDE: inc/CryptX_Mac_F9.xs.inc
INCLUDE: inc/CryptX_Mac_HMAC.xs.inc
INCLUDE: inc/CryptX_Mac_OMAC.xs.inc
INCLUDE: inc/CryptX_Mac_Pelican.xs.inc
INCLUDE: inc/CryptX_Mac_PMAC.xs.inc
INCLUDE: inc/CryptX_Mac_XCBC.xs.inc

INCLUDE: inc/CryptX_Mode_CBC.xs.inc
INCLUDE: inc/CryptX_Mode_ECB.xs.inc
INCLUDE: inc/CryptX_Mode_CFB.xs.inc
INCLUDE: inc/CryptX_Mode_OFB.xs.inc
INCLUDE: inc/CryptX_Mode_CTR.xs.inc
#INCLUDE: inc/CryptX_Mode_F8.xs.inc
#INCLUDE: inc/CryptX_Mode_LRW.xs.inc
#INCLUDE: inc/CryptX_Mode_XTS.xs.inc

INCLUDE: inc/CryptX_PRNG.xs.inc

INCLUDE: inc/CryptX_PK_RSA.xs.inc
INCLUDE: inc/CryptX_PK_DSA.xs.inc
INCLUDE: inc/CryptX_PK_DH.xs.inc
INCLUDE: inc/CryptX_PK_ECC.xs.inc

INCLUDE: inc/CryptX_KeyDerivation.xs.inc

INCLUDE: inc/CryptX_BigInt_LTM.xs.inc
