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
        int rv;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        in_data = (unsigned char *) SvPVbyte(in, in_len);
        out_len = (unsigned long)(4 * ((in_len + 2) / 3) + 1);
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
        out_len = (unsigned long)in_len;
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
        out_len = (unsigned long)(4 * ((in_len + 2) / 3) + 1);
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
        out_len = (unsigned long)in_len;
        Newz(0, out_data, out_len, unsigned char);
        if (!out_data) croak("FATAL: Newz failed [%ld]", out_len);
        rv = base64_decode(in_data, (unsigned long)in_len, out_data, &out_len);
        RETVAL = (rv == CRYPT_OK) ? newSVpvn((char *)out_data, out_len) : newSVpvn(NULL, 0);
        Safefree(out_data);
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
        in_data = (unsigned char *) SvPVbyte(in, len);
        if (len == 0) XSRETURN_UNDEF;

        RETVAL = NEWSV(0, len);
        SvPOK_only(RETVAL);
        SvCUR_set(RETVAL, len);
        out_data = (unsigned char *)SvPV_nolen(RETVAL);
        Copy(in_data, out_data, len, unsigned char);
        while (i < len) {
          out_data[i]++;
          if (0 != out_data[i]) break;
          i++;
        }
        if (i == len) croak("FATAL: increment_octets_le overflow");
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
        in_data = (unsigned char *) SvPVbyte(in, len);
        if (len == 0) XSRETURN_UNDEF;

        RETVAL = NEWSV(0, len);
        SvPOK_only(RETVAL);
        SvCUR_set(RETVAL, len);
        out_data = (unsigned char *)SvPV_nolen(RETVAL);
        Copy(in_data, out_data, len, unsigned char);
        while (i < len) {
          out_data[len - 1 - i]++;
          if (0 != out_data[len - 1 - i]) break;
          i++;
        }
        if (i == len) croak("FATAL: increment_octets_le overflow");
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
          out_data = (unsigned char *)SvPV_nolen(RETVAL);
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
          out_data = SvPV_nolen(RETVAL);
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
CryptX__encode_b32(SV *bytes, unsigned idx)
    CODE:
    {
        STRLEN inlen, outlen, i, leven;
        unsigned char *out, *in, *codes;
        char *alphabet[] = {
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",     /* rfc4648 */
                "0123456789ABCDEFGHIJKLMNOPQRSTUV",     /* base32hex */
                "ybndrfg8ejkmcpqxot1uwisza345h769",     /* zbase32 */
                "0123456789ABCDEFGHJKMNPQRSTVWXYZ"      /* crockford */
        };

        if (!SvOK(bytes)) {
          /* for undefined input return "" (empty string) */
          RETVAL = newSVpv("", 0);
        }
        else {
          if (!SvPOK(bytes) || idx > 3) XSRETURN_UNDEF;         /* error */
          in = (unsigned char *) SvPVbyte(bytes, inlen);
          if (in == NULL) XSRETURN_UNDEF;                       /* error */
          if (inlen == 0) {
            RETVAL = newSVpv("", 0);
          }
          else {
            codes = (unsigned char*)alphabet[idx];
            outlen = (8 * inlen + 4) / 5;
            RETVAL = NEWSV(0, outlen);
            SvPOK_only(RETVAL);
            SvCUR_set(RETVAL, outlen);
            out = (unsigned char *)SvPV_nolen(RETVAL);

            leven = 5 * (inlen / 5);
            for (i = 0; i < leven; i += 5) {
              *out++ = codes[(in[0] >> 3) & 0x1F];
              *out++ = codes[(((in[0] & 0x7) << 2) + (in[1] >> 6)) & 0x1F];
              *out++ = codes[(in[1] >> 1) & 0x1F];
              *out++ = codes[(((in[1] & 0x1) << 4) + (in[2] >> 4)) & 0x1F];
              *out++ = codes[(((in[2] & 0xF) << 1) + (in[3] >> 7)) & 0x1F];
              *out++ = codes[(in[3] >> 2) & 0x1F];
              *out++ = codes[(((in[3] & 0x3) << 3) + (in[4] >> 5)) & 0x1F];
              *out++ = codes[in[4] & 0x1F];
              in += 5;
            }
            if (i < inlen) {
              unsigned a = in[0];
              unsigned b = (i+1 < inlen) ? in[1] : 0;
              unsigned c = (i+2 < inlen) ? in[2] : 0;
              unsigned d = (i+3 < inlen) ? in[3] : 0;
              *out++ = codes[(a >> 3) & 0x1F];
              *out++ = codes[(((a & 0x7) << 2) + (b >> 6)) & 0x1F];
              if (i+1 < inlen) {
                *out++ = codes[(b >> 1) & 0x1F];
                *out++ = codes[(((b & 0x1) << 4) + (c >> 4)) & 0x1F];
              }
              if (i+2 < inlen) {
                *out++ = codes[(((c & 0xF) << 1) + (d >> 7)) & 0x1F];
                *out++ = codes[(d >> 2) & 0x1F];
              }
              if (i+3 < inlen) {
                *out++ = codes[((d & 0x3) << 3) & 0x1F];
              }
            }
          }
        }
    }
    OUTPUT:
        RETVAL

SV *
CryptX__decode_b32(SV *base32, unsigned idx)
    CODE:
    {
        STRLEN x, inlen, outlen;
        int y = 0;
        ulong64 t = 0;
        unsigned char c, *in, *out, *map;
        unsigned char tables[4][43] = {
          {  /* rfc4648 ABCDEFGHIJKLMNOPQRSTUVWXYZ234567 */
             99/*0*/,99/*1*/,26/*2*/,27/*3*/,28/*4*/,29/*5*/,30/*6*/,31/*7*/,99/*8*/,99/*9*/,
             99/*:*/,99/*;*/,99/*<*/,99/*=*/,99/*>*/,99/*?*/,99/*@*/,
              0/*A*/, 1/*B*/, 2/*C*/, 3/*D*/, 4/*E*/, 5/*F*/, 6/*G*/, 7/*H*/, 8/*I*/, 9/*J*/,10/*K*/,11/*L*/,12/*M*/,
             13/*N*/,14/*O*/,15/*P*/,16/*Q*/,17/*R*/,18/*S*/,19/*T*/,20/*U*/,21/*V*/,22/*W*/,23/*X*/,24/*Y*/,25/*Z*/
          },
          {  /* base32hex 0123456789ABCDEFGHIJKLMNOPQRSTUV */
               0/*0*/, 1/*1*/, 2/*2*/, 3/*3*/, 4/*4*/, 5/*5*/, 6/*6*/, 7/*7*/, 8/*8*/, 9/*9*/,
              99/*:*/,99/*;*/,99/*<*/,99/*=*/,99/*>*/,99/*?*/,99/*@*/,
              10/*A*/,11/*B*/,12/*C*/,13/*D*/,14/*E*/,15/*F*/,16/*G*/,17/*H*/,18/*I*/,19/*J*/,20/*K*/,21/*L*/,22/*M*/,
              23/*N*/,24/*O*/,25/*P*/,26/*Q*/,27/*R*/,28/*S*/,29/*T*/,30/*U*/,31/*V*/,99/*W*/,99/*X*/,99/*Y*/,99/*Z*/
          },
          {  /* zbase32 YBNDRFG8EJKMCPQXOT1UWISZA345H769 */
             99/*0*/,18/*1*/,99/*2*/,25/*3*/,26/*4*/,27/*5*/,30/*6*/,29/*7*/, 7/*8*/,31/*9*/,
             99/*:*/,99/*;*/,99/*<*/,99/*=*/,99/*>*/,99/*?*/,99/*@*/,
             24/*A*/, 1/*B*/,12/*C*/, 3/*D*/, 8/*E*/, 5/*F*/, 6/*G*/,28/*H*/,21/*I*/, 9/*J*/,10/*K*/,99/*L*/,11/*M*/,
              2/*N*/,16/*O*/,13/*P*/,14/*Q*/, 4/*R*/,22/*S*/,17/*T*/,19/*U*/,99/*V*/,20/*W*/,15/*X*/, 0/*Y*/,23/*Z*/
          },
          {  /* crockford 0123456789ABCDEFGHJKMNPQRSTVWXYZ + O=>0 + IL=>1 */
              0/*0*/, 1/*1*/, 2/*2*/, 3/*3*/, 4/*4*/, 5/*5*/, 6/*6*/, 7/*7*/, 8/*8*/, 9/*9*/,
             99/*:*/,99/*;*/,99/*<*/,99/*=*/,99/*>*/,99/*?*/,99/*@*/,
             10/*A*/,11/*B*/,12/*C*/,13/*D*/,14/*E*/,15/*F*/,16/*G*/,17/*H*/, 1/*I*/,18/*J*/,19/*K*/, 1/*L*/,20/*M*/,
             21/*N*/, 0/*O*/,22/*P*/,23/*Q*/,24/*R*/,25/*S*/,26/*T*/,99/*U*/,27/*V*/,28/*W*/,29/*X*/,30/*Y*/,31/*Z*/
          }
        };

        if (!SvOK(base32)) {
          /* for undefined input return "" (empty string) */
          RETVAL = newSVpv("", 0);
        }
        else {
          if (!SvPOK(base32) || idx > 3) XSRETURN_UNDEF;                /* error */
          in = (unsigned char *) SvPVbyte(base32, inlen);
          if (in == NULL) XSRETURN_UNDEF;                               /* error */

          while (inlen>0 && in[inlen-1] == '=') inlen--;
          if (inlen == 0) {
            RETVAL = newSVpv("", 0);
          }
          else {
            x = inlen % 8;
            if (x == 1 || x == 3 || x == 6) XSRETURN_UNDEF;             /* error */
            outlen = (inlen * 5) / 8;
            RETVAL = NEWSV(0, outlen);
            SvPOK_only(RETVAL);
            SvCUR_set(RETVAL, outlen);
            out = (unsigned char *)SvPV_nolen(RETVAL);
            map = tables[idx];
            for (x = 0; x < inlen; x++) {
              c = in[x];
              /* convert to upper case */
              if ((c >= 'a') && (c <= 'z')) c -= 32;
              /* '0' = 48 .. 'Z' = 90 */
              if (c < 48 || c > 90 || map[c-48] > 31) XSRETURN_UNDEF;   /* error */
              t = (t<<5)|map[c-48];
              if (++y == 8) {
                *out++ = (unsigned char)((t>>32) & 255);
                *out++ = (unsigned char)((t>>24) & 255);
                *out++ = (unsigned char)((t>>16) & 255);
                *out++ = (unsigned char)((t>> 8) & 255);
                *out++ = (unsigned char)( t      & 255);
                y = 0;
                t = 0;
              }
            }
            if (y > 0) {
              t = t << (5 * (8 - y));
              if (y >= 2) *out++ = (unsigned char)((t>>32) & 255);
              if (y >= 4) *out++ = (unsigned char)((t>>24) & 255);
              if (y >= 5) *out++ = (unsigned char)((t>>16) & 255);
              if (y >= 7) *out++ = (unsigned char)((t>> 8) & 255);
            }
          }
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
