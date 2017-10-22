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

typedef struct digest_shake_struct {    /* used by Crypt::Digest::SHAKE */
  hash_state state;
  int num;
} *Crypt__Digest__SHAKE;

typedef struct ccm_struct {             /* used by Crypt::AuthEnc::CCM */
  ccm_state state;
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

typedef struct chacha20poly1305_struct {/* used by Crypt::AuthEnc::ChaCha20Poly1305 */
  chacha20poly1305_state state;
  int id;
} *Crypt__AuthEnc__ChaCha20Poly1305;

typedef struct ocb_struct {             /* used by Crypt::AuthEnc::OCB */
  ocb3_state state;
  int id;
} *Crypt__AuthEnc__OCB;

typedef struct chacha_struct {          /* used by Crypt::Stream::ChaCha */
  chacha_state state;
  int id;
} *Crypt__Stream__ChaCha;

typedef struct rc4_struct {             /* used by Crypt::Stream::RC4 */
  rc4_state state;
  int id;
} *Crypt__Stream__RC4;

typedef struct sober128_struct {        /* used by Crypt::Stream::Sober128 */
  sober128_state state;
  int id;
} *Crypt__Stream__Sober128;

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

typedef struct poly1305_struct {        /* used by Crypt::Mac::Poly1305 */
  poly1305_state state;
  int id;
} *Crypt__Mac__Poly1305;

typedef struct blake2s_struct {         /* used by Crypt::Mac::BLAKE2s */
  blake2smac_state state;
  int id;
} *Crypt__Mac__BLAKE2s;

typedef struct blake2b_struct {         /* used by Crypt::Mac::BLAKE2b */
  blake2bmac_state state;
  int id;
} *Crypt__Mac__BLAKE2b;

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
  prng_state pstate;
  int pindex;
  rsa_key key;
  int id;
} *Crypt__PK__RSA;

typedef struct dsa_struct {             /* used by Crypt::PK::DSA */
  prng_state pstate;
  int pindex;
  dsa_key key;
  int id;
} *Crypt__PK__DSA;

typedef struct dh_struct {              /* used by Crypt::PK::DH */
  prng_state pstate;
  int pindex;
  dh_key key;
  int id;
} *Crypt__PK__DH;

typedef struct ecc_struct {             /* used by Crypt::PK::ECC */
  prng_state pstate;
  int pindex;
  ecc_key key;
  ltc_ecc_set_type dp;
  int id;
} *Crypt__PK__ECC;

int str_add_leading_zero(char *str, int maxlen, int minlen) {
  int len;
  len = (int)strlen(str);
  if (len > 0 && len % 2 && len < maxlen-2) {
    memmove(str+1, str, len+1); /* incl. NUL byte */
    *str = '0';                 /* add leading zero */
  }
  len = (int)strlen(str);
  if (len < minlen && minlen < maxlen-1) {
    memmove(str+(minlen-len), str, len+1); /* incl. NUL byte */
    memset(str, '0', minlen-len);          /* add leading zero */
  }
  return MP_OKAY;
}

int mp_tohex_with_leading_zero(mp_int * a, char *str, int maxlen, int minlen) {
  int rv;
  if (mp_isneg(a) == MP_YES) {
    *str = '\0';
    return MP_VAL;
  }
  rv = mp_toradix_n(a, str, 16, maxlen);
  if (rv != MP_OKAY) {
    *str = '\0';
    return rv;
  }
  return str_add_leading_zero(str, maxlen, minlen);
}

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
  SV **sv_cofactor, **sv_prime, **sv_A, **sv_B, **sv_order, **sv_Gx, **sv_Gy;
  int err;
  char *ch_name;
  STRLEN l_name;

  if (SvPOK(curve)) {
    ch_name = SvPV(curve, l_name);
    if ((h = get_hv("Crypt::PK::ECC::curve", 0)) == NULL) croak("FATAL: generate_key_ex: no curve register");
    if ((pref = hv_fetch(h, ch_name, (U32)l_name, 0)) == NULL)  croak("FATAL: generate_key_ex: unknown curve/1 '%s'", ch_name);
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

PROTOTYPES: DISABLE

BOOT:
    if(register_all_ciphers() != CRYPT_OK)     { croak("FATAL: register_all_ciphers failed"); }
    if(register_all_hashes()  != CRYPT_OK)     { croak("FATAL: register_all_hashes failed"); }
    if(register_all_prngs()   != CRYPT_OK)     { croak("FATAL: register_all_prngs failed"); }
    if(crypt_mp_init("ltm")   != CRYPT_OK)     { croak("FATAL: crypt_mp_init failed"); }

SV *
CryptX__encode_base64url(SV * in)
    CODE:
    {
        STRLEN in_len;
        unsigned long out_len;
        unsigned char *out_data, *in_data;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        in_data = (unsigned char *) SvPVbyte(in, in_len);
        if (in_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          out_len = (unsigned long)(4 * ((in_len + 2) / 3) + 1);
          RETVAL = NEWSV(0, out_len);
          SvPOK_only(RETVAL);
          out_data = (unsigned char *)SvPVX(RETVAL);
          if (base64url_encode(in_data, (unsigned long)in_len, out_data, &out_len) != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            XSRETURN_UNDEF;
          }
          SvCUR_set(RETVAL, out_len);
        }
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

        if (!SvPOK(in)) XSRETURN_UNDEF;
        in_data = (unsigned char *) SvPVbyte(in, in_len);
        if (in_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          out_len = (unsigned long)in_len;
          RETVAL = NEWSV(0, out_len);
          SvPOK_only(RETVAL);
          out_data = (unsigned char *)SvPVX(RETVAL);
          if (base64url_decode(in_data, (unsigned long)in_len, out_data, &out_len) != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            XSRETURN_UNDEF;
          }
          SvCUR_set(RETVAL, out_len);
        }
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

        if (!SvPOK(in)) XSRETURN_UNDEF;
        in_data = (unsigned char *) SvPVbyte(in, in_len);
        if (in_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          out_len = (unsigned long)(4 * ((in_len + 2) / 3) + 1);
          RETVAL = NEWSV(0, out_len);
          SvPOK_only(RETVAL);
          out_data = (unsigned char *)SvPVX(RETVAL);
          if (base64_encode(in_data, (unsigned long)in_len, out_data, &out_len) != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            XSRETURN_UNDEF;
          }
          SvCUR_set(RETVAL, out_len);
        }
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

        if (!SvPOK(in)) XSRETURN_UNDEF;
        in_data = (unsigned char *)SvPVbyte(in, in_len);
        if (in_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          out_len = (unsigned long)in_len;
          RETVAL = NEWSV(0, out_len);
          SvPOK_only(RETVAL);
          out_data = (unsigned char *)SvPVX(RETVAL);
          if (base64_decode(in_data, (unsigned long)in_len, out_data, &out_len) != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            XSRETURN_UNDEF;
          }
          SvCUR_set(RETVAL, out_len);
        }
    }
    OUTPUT:
        RETVAL

SV *
CryptX__encode_b32(SV *in, unsigned idx)
    CODE:
    {
        STRLEN in_len;
        unsigned long out_len;
        unsigned char *out_data, *in_data;
        int id = -1;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        if (idx == 0) id = BASE32_RFC4648;
        if (idx == 1) id = BASE32_BASE32HEX;
        if (idx == 2) id = BASE32_ZBASE32;
        if (idx == 3) id = BASE32_CROCKFORD;
        if (id == -1) XSRETURN_UNDEF;
        in_data = (unsigned char *) SvPVbyte(in, in_len);
        if (in_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          out_len = (unsigned long)((8 * in_len + 4) / 5);
          RETVAL = NEWSV(0, out_len);
          SvPOK_only(RETVAL);
          out_data = (unsigned char *)SvPVX(RETVAL);
          if (base32_encode(in_data, (unsigned long)in_len, out_data, &out_len, id) != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            XSRETURN_UNDEF;
          }
          SvCUR_set(RETVAL, out_len);
        }
    }
    OUTPUT:
        RETVAL

SV *
CryptX__decode_b32(SV *in, unsigned idx)
    CODE:
    {
        STRLEN in_len;
        unsigned long out_len;
        unsigned char *out_data, *in_data;
        int id = -1;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        if (idx == 0) id = BASE32_RFC4648;
        if (idx == 1) id = BASE32_BASE32HEX;
        if (idx == 2) id = BASE32_ZBASE32;
        if (idx == 3) id = BASE32_CROCKFORD;
        if (id == -1) XSRETURN_UNDEF;
        in_data = (unsigned char *)SvPVbyte(in, in_len);
        if (in_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          out_len = (unsigned long)in_len;
          RETVAL = NEWSV(0, out_len);
          SvPOK_only(RETVAL);
          out_data = (unsigned char *)SvPVX(RETVAL);
          if (base32_decode(in_data, (unsigned long)in_len, out_data, &out_len, id) != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            XSRETURN_UNDEF;
          }
          SvCUR_set(RETVAL, out_len);
        }
    }
    OUTPUT:
        RETVAL

SV *
CryptX__increment_octets_le(SV * in)
    CODE:
    {
        STRLEN len, i = 0;
        unsigned char *out_data, *in_data;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        in_data = (unsigned char *)SvPVbyte(in, len);
        if (len == 0) XSRETURN_UNDEF;

        RETVAL = NEWSV(0, len);
        SvPOK_only(RETVAL);
        SvCUR_set(RETVAL, len);
        out_data = (unsigned char *)SvPVX(RETVAL);
        Copy(in_data, out_data, len, unsigned char);
        while (i < len) {
          out_data[i]++;
          if (0 != out_data[i]) break;
          i++;
        }
        if (i == len) {
          SvREFCNT_dec(RETVAL);
          croak("FATAL: increment_octets_le overflow");
        }
    }
    OUTPUT:
        RETVAL

SV *
CryptX__increment_octets_be(SV * in)
    CODE:
    {
        STRLEN len, i = 0;
        unsigned char *out_data, *in_data;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        in_data = (unsigned char *)SvPVbyte(in, len);
        if (len == 0) XSRETURN_UNDEF;

        RETVAL = NEWSV(0, len);
        SvPOK_only(RETVAL);
        SvCUR_set(RETVAL, len);
        out_data = (unsigned char *)SvPVX(RETVAL);
        Copy(in_data, out_data, len, unsigned char);
        while (i < len) {
          out_data[len - 1 - i]++;
          if (0 != out_data[len - 1 - i]) break;
          i++;
        }
        if (i == len) {
          SvREFCNT_dec(RETVAL);
          croak("FATAL: increment_octets_be overflow");
        }
    }
    OUTPUT:
        RETVAL

SV *
CryptX__radix_to_bin(char *in, int radix)
    CODE:
    {
        STRLEN len;
        unsigned char *out_data;
        mp_int mpi;

        if (in == NULL || strlen(in) == 0)      XSRETURN_UNDEF;

        if (mp_init(&mpi) != CRYPT_OK)          XSRETURN_UNDEF;

        if (mp_read_radix(&mpi, in, radix) == CRYPT_OK) {
          len = mp_unsigned_bin_size(&mpi);
          RETVAL = NEWSV(0, len);
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, len);
          out_data = (unsigned char *)SvPVX(RETVAL);
          mp_to_unsigned_bin(&mpi, out_data);
          mp_clear(&mpi);
        }
        else {
          XSRETURN_UNDEF;
        }
    }
    OUTPUT:
        RETVAL

SV *
CryptX__bin_to_radix(SV *in, int radix)
    CODE:
    {
        STRLEN len;
        unsigned char *in_data;
        char *out_data;
        mp_int mpi, tmp;
        mp_digit d;
        int digits = 0;

        if (!SvPOK(in) || radix < 2 || radix > 64) XSRETURN_UNDEF;
        in_data = (unsigned char *) SvPVbyte(in, len);
        if (len == 0) XSRETURN_UNDEF;

        mp_init(&mpi);
        if (mp_read_unsigned_bin(&mpi, in_data, len) == CRYPT_OK) {
          mp_init_copy(&tmp, &mpi);
          while (mp_iszero(&tmp) == MP_NO) {
            mp_div_d(&tmp, (mp_digit)radix, &tmp, &d);
            digits++;
          }
          mp_clear(&tmp);

          RETVAL = NEWSV(0, digits + 1);
          SvPOK_only(RETVAL);
          out_data = SvPVX(RETVAL);
          mp_toradix(&mpi, out_data, radix);
          SvCUR_set(RETVAL, digits);
          mp_clear(&mpi);
        }
        else {
          XSRETURN_UNDEF;
        }
    }
    OUTPUT:
        RETVAL

SV *
CryptX__ltc_build_settings()
    CODE:
        RETVAL = newSVpv(crypt_build_settings, 0);
    OUTPUT:
        RETVAL

SV *
CryptX__ltc_mp_name()
    CODE:
        RETVAL = newSVpv(ltc_mp.name, 0);
    OUTPUT:
        RETVAL

int
CryptX__ltc_mp_bits_per_digit()
    CODE:
        RETVAL = ltc_mp.bits_per_digit;
    OUTPUT:
        RETVAL

###############################################################################

INCLUDE: inc/CryptX_Digest.xs.inc
INCLUDE: inc/CryptX_Digest_SHAKE.xs.inc
INCLUDE: inc/CryptX_Cipher.xs.inc

INCLUDE: inc/CryptX_Checksum_Adler32.xs.inc
INCLUDE: inc/CryptX_Checksum_CRC32.xs.inc

INCLUDE: inc/CryptX_AuthEnc_EAX.xs.inc
INCLUDE: inc/CryptX_AuthEnc_GCM.xs.inc
INCLUDE: inc/CryptX_AuthEnc_OCB.xs.inc
INCLUDE: inc/CryptX_AuthEnc_CCM.xs.inc
INCLUDE: inc/CryptX_AuthEnc_ChaCha20Poly1305.xs.inc

INCLUDE: inc/CryptX_Stream_ChaCha.xs.inc
INCLUDE: inc/CryptX_Stream_RC4.xs.inc
INCLUDE: inc/CryptX_Stream_Sober128.xs.inc

INCLUDE: inc/CryptX_Mac_F9.xs.inc
INCLUDE: inc/CryptX_Mac_HMAC.xs.inc
INCLUDE: inc/CryptX_Mac_OMAC.xs.inc
INCLUDE: inc/CryptX_Mac_Pelican.xs.inc
INCLUDE: inc/CryptX_Mac_PMAC.xs.inc
INCLUDE: inc/CryptX_Mac_XCBC.xs.inc
INCLUDE: inc/CryptX_Mac_Poly1305.xs.inc
INCLUDE: inc/CryptX_Mac_BLAKE2s.xs.inc
INCLUDE: inc/CryptX_Mac_BLAKE2b.xs.inc

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
