#define PERL_NO_GET_CONTEXT     /* we want efficiency */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define NEED_sv_2pvbyte_GLOBAL
#define NEED_sv_2pv_flags_GLOBAL
#define NEED_newRV_noinc_GLOBAL
#include "ppport.h"

/* assert_not_ROK is broken in 5.8.1 */
#if PERL_VERSION == 8 && PERL_SUBVERSION == 1
# undef assert_not_ROK
# if defined(__GNUC__) && !defined(PERL_GCC_BRACE_GROUPS_FORBIDDEN)
#  define assert_not_ROK(sv)  ({assert(!SvROK(sv) || !SvRV(sv));}),
# else
#  define assert_not_ROK(sv)
# endif
#endif

#undef LTC_SOURCE
#include "tomcrypt.h"
#include "tommath.h"

typedef adler32_state           *Crypt__Checksum__Adler32;
typedef crc32_state             *Crypt__Checksum__CRC32;

typedef ccm_state               *Crypt__AuthEnc__CCM;
typedef eax_state               *Crypt__AuthEnc__EAX;
typedef gcm_state               *Crypt__AuthEnc__GCM;
typedef chacha20poly1305_state  *Crypt__AuthEnc__ChaCha20Poly1305;
typedef ocb3_state              *Crypt__AuthEnc__OCB;

typedef chacha_state            *Crypt__Stream__ChaCha;
typedef salsa20_state           *Crypt__Stream__Salsa20;
typedef sosemanuk_state         *Crypt__Stream__Sosemanuk;
typedef rabbit_state            *Crypt__Stream__Rabbit;
typedef rc4_state               *Crypt__Stream__RC4;
typedef sober128_state          *Crypt__Stream__Sober128;

typedef f9_state                *Crypt__Mac__F9;
typedef hmac_state              *Crypt__Mac__HMAC;
typedef omac_state              *Crypt__Mac__OMAC;
typedef pelican_state           *Crypt__Mac__Pelican;
typedef pmac_state              *Crypt__Mac__PMAC;
typedef xcbc_state              *Crypt__Mac__XCBC;
typedef poly1305_state          *Crypt__Mac__Poly1305;
typedef blake2smac_state        *Crypt__Mac__BLAKE2s;
typedef blake2bmac_state        *Crypt__Mac__BLAKE2b;

typedef struct cipher_struct {          /* used by Crypt::Cipher */
  symmetric_key skey;
  struct ltc_cipher_descriptor *desc;
} *Crypt__Cipher;

typedef struct digest_struct {          /* used by Crypt::Digest */
  hash_state state;
  struct ltc_hash_descriptor *desc;
} *Crypt__Digest;

typedef struct digest_shake_struct {    /* used by Crypt::Digest::SHAKE */
  hash_state state;
  int num;
} *Crypt__Digest__SHAKE;

typedef struct cbc_struct {             /* used by Crypt::Mode::CBC */
  int cipher_id, cipher_rounds;
  symmetric_CBC state;
  unsigned char pad[MAXBLOCKSIZE];
  int padlen;
  int padding_mode;
  int direction;
} *Crypt__Mode__CBC;

typedef struct ecb_struct {             /* used by Crypt::Mode::ECB */
  int cipher_id, cipher_rounds;
  symmetric_ECB state;
  unsigned char pad[MAXBLOCKSIZE];
  int padlen;
  int padding_mode;
  int direction;
} *Crypt__Mode__ECB;

typedef struct cfb_struct {             /* used by Crypt::Mode::CFB */
  int cipher_id, cipher_rounds;
  symmetric_CFB state;
  int direction;
} *Crypt__Mode__CFB;

typedef struct ctr_struct {             /* used by Crypt::Mode::CTR */
  int cipher_id, cipher_rounds;
  int ctr_mode_param;
  symmetric_CTR state;
  int direction;
} *Crypt__Mode__CTR;

typedef struct f8_struct {              /* used by Crypt::Mode::F8 */
  int cipher_id, cipher_rounds;
  symmetric_F8 state;
  int direction;
} *Crypt__Mode__F8;

typedef struct lrw_struct {             /* used by Crypt::Mode::LRW */
  int cipher_id, cipher_rounds;
  symmetric_LRW state;
  int direction;
} *Crypt__Mode__LRW;

typedef struct ofb_struct {             /* used by Crypt::Mode::OFB */
  int cipher_id, cipher_rounds;
  symmetric_OFB state;
  int direction;
} *Crypt__Mode__OFB;

typedef struct xts_struct {             /* used by Crypt::Mode::XTS */
  int cipher_id, cipher_rounds;
  symmetric_xts state;
  int direction;
} *Crypt__Mode__XTS;

typedef struct prng_struct {            /* used by Crypt::PRNG */
  prng_state state;
  struct ltc_prng_descriptor *desc;
  IV last_pid;
} *Crypt__PRNG;

typedef struct rsa_struct {             /* used by Crypt::PK::RSA */
  prng_state pstate;
  int pindex;
  rsa_key key;
} *Crypt__PK__RSA;

typedef struct dsa_struct {             /* used by Crypt::PK::DSA */
  prng_state pstate;
  int pindex;
  dsa_key key;
} *Crypt__PK__DSA;

typedef struct dh_struct {              /* used by Crypt::PK::DH */
  prng_state pstate;
  int pindex;
  dh_key key;
} *Crypt__PK__DH;

typedef struct ecc_struct {             /* used by Crypt::PK::ECC */
  prng_state pstate;
  int pindex;
  ecc_key key;
} *Crypt__PK__ECC;

typedef struct ed25519_struct {         /* used by Crypt::PK::Ed25519 */
  prng_state pstate;
  int pindex;
  curve25519_key key;
  int initialized;
} *Crypt__PK__Ed25519;

typedef struct x25519_struct {          /* used by Crypt::PK::X25519 */
  prng_state pstate;
  int pindex;
  curve25519_key key;
  int initialized;
} *Crypt__PK__X25519;

int mp_tohex_with_leading_zero(mp_int * a, char *str, int maxlen, int minlen) {
  int len, rv;

  if (mp_isneg(a) == MP_YES) {
    *str = '\0';
    return MP_VAL;
  }

  rv = mp_toradix_n(a, str, 16, maxlen);
  if (rv != MP_OKAY) {
    *str = '\0';
    return rv;
  }

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

size_t _find_start(const char *name, char *ltcname, size_t ltclen)
{
   size_t i, start = 0;
   if (name == NULL || strlen(name) + 1 > ltclen) croak("FATAL: invalid name") ;
   /* normalize */
   for (i = 0; i < ltclen && name[i] > 0; i++) {
     if (name[i] >= 'A' && name[i] <= 'Z') {
       ltcname[i] = name[i] + 32; /* lowecase */
     }
     else if (name[i] == '_') {
       ltcname[i] = '-';
     }
     else {
       ltcname[i] = name[i];
     }
     if (name[i] == ':') start = i + 1;
   }
   return start;
}

int _find_hash(const char *name)
{
   char ltcname[100] = { 0 };
   size_t start = _find_start(name, ltcname, sizeof(ltcname) - 1);
   /* special cases */
   if (strcmp(ltcname + start, "ripemd128") == 0) return find_hash("rmd128");
   if (strcmp(ltcname + start, "ripemd160") == 0) return find_hash("rmd160");
   if (strcmp(ltcname + start, "ripemd256") == 0) return find_hash("rmd256");
   if (strcmp(ltcname + start, "ripemd320") == 0) return find_hash("rmd320");
   if (strcmp(ltcname + start, "tiger192")  == 0) return find_hash("tiger");
   if (strcmp(ltcname + start, "chaes")     == 0) return find_hash("chc_hash");
   if (strcmp(ltcname + start, "chc-hash")  == 0) return find_hash("chc_hash");
   return find_hash(ltcname + start);
}

int _find_cipher(const char *name)
{
   char ltcname[100] = { 0 };
   size_t start = _find_start(name, ltcname, sizeof(ltcname) - 1);
   /* special cases */
   if (strcmp(ltcname + start, "des-ede") == 0) return find_cipher("3des");
   if (strcmp(ltcname + start, "saferp")  == 0) return find_cipher("safer+");
   return find_cipher(ltcname + start);
}

int _find_prng(const char *name)
{
  char ltcname[100] = { 0 };
  size_t start = _find_start(name, ltcname, sizeof(ltcname) - 1);
  return find_prng(ltcname + start);
}

/* Math::BigInt::LTM related */
typedef mp_int * Math__BigInt__LTM;
STATIC SV * sv_from_mpi(mp_int *mpi) {
  dTHX; /* fetch context */
  SV *obj = newSV(0);
  sv_setref_pv(obj, "Math::BigInt::LTM", (void*)mpi);
  return obj;
}

void _ecc_oid_lookup(ecc_key *key)
{
   int err;
   unsigned i, j;
   void *tmp;
   const ltc_ecc_curve *cu;

   key->dp.oidlen = 0;
   if ((err = ltc_mp.init(&tmp)) != CRYPT_OK) return;
   for (cu = ltc_ecc_curves; cu->prime != NULL; cu++) {
      if ((err = mp_read_radix(tmp, cu->prime, 16)) != CRYPT_OK) continue;
      if ((mp_cmp(tmp, key->dp.prime) != LTC_MP_EQ))             continue;
      if ((err = mp_read_radix(tmp, cu->order, 16)) != CRYPT_OK) continue;
      if ((mp_cmp(tmp, key->dp.order) != LTC_MP_EQ))             continue;
      if ((err = mp_read_radix(tmp, cu->A,     16)) != CRYPT_OK) continue;
      if ((mp_cmp(tmp, key->dp.A) != LTC_MP_EQ))                 continue;
      if ((err = mp_read_radix(tmp, cu->B,     16)) != CRYPT_OK) continue;
      if ((mp_cmp(tmp, key->dp.B) != LTC_MP_EQ))                 continue;
      if ((err = mp_read_radix(tmp, cu->Gx,    16)) != CRYPT_OK) continue;
      if ((mp_cmp(tmp, key->dp.base.x) != LTC_MP_EQ))            continue;
      if ((err = mp_read_radix(tmp, cu->Gy,    16)) != CRYPT_OK) continue;
      if ((mp_cmp(tmp, key->dp.base.y) != LTC_MP_EQ))            continue;
      if (key->dp.cofactor != cu->cofactor)                      continue;
      break; /* found */
   }
   ltc_mp.deinit(tmp);
   if (cu->prime && cu->OID) {
     for (i = 0; i < 16; i++) key->dp.oid[i] = 0;
     for (i = 0, j = 0; i < strlen(cu->OID); i++) {
       if (cu->OID[i] == '.') {
         if (++j >= 16) return;
       }
       else if(cu->OID[i] >= '0' && cu->OID[i] <= '9') {
         key->dp.oid[j] = key->dp.oid[j] * 10 + (cu->OID[i] - '0');
       }
       else {
         return;
       }
     }
     key->dp.oidlen = j + 1;
   }
}

int _ecc_set_curve_from_SV(ecc_key *key, SV *curve)
{
  dTHX; /* fetch context */
  HV *hc, *h;
  SV *sv_crv, **pref;
  SV **sv_cofactor, **sv_prime, **sv_A, **sv_B, **sv_order, **sv_Gx, **sv_Gy, **sv_oid;
  char *ptr_crv;
  STRLEN len_crv;
  int err;

  if (!SvOK(curve)) croak("FATAL: undefined curve");

  if (SvPOK(curve)) {
    /* string */
    ptr_crv = SvPV(curve, len_crv);
    if ((hc = get_hv("Crypt::PK::ECC::curve", 0)) == NULL) croak("FATAL: no curve register");
    pref = hv_fetch(hc, ptr_crv, (U32)len_crv, 0);
    if (pref && SvOK(*pref)) {
      sv_crv = *pref; /* found in %curve */
    }
    else {
      sv_crv = curve;
    }
  }
  else if (SvROK(curve) && SvTYPE(SvRV(curve)) == SVt_PVHV) {
    /* hashref */
    sv_crv = curve;
  }
  else {
    croak("FATAL: curve has to be a string or a hashref");
  }

  if (SvPOK(sv_crv)) {
    /* string - curve name */
    const ltc_ecc_curve *cu;
    ptr_crv = SvPV(sv_crv, len_crv);
    if (ecc_find_curve(ptr_crv, &cu) != CRYPT_OK) croak("FATAL: ecparams: unknown curve '%s'", ptr_crv);
    return ecc_set_curve(cu, key);
  }
  else {
    /* hashref */
    ltc_ecc_curve cu = { 0 };

    if ((h = (HV*)(SvRV(sv_crv))) == NULL) croak("FATAL: ecparams: param is not valid hashref");

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

    sv_oid = hv_fetchs(h, "oid", 0); /* 'oid' is optional */
    cu.OID = (sv_oid && SvOK(*sv_oid)) ? SvPV_nolen(*sv_oid) : NULL;

    cu.prime    = SvPV_nolen(*sv_prime);
    cu.A        = SvPV_nolen(*sv_A);
    cu.B        = SvPV_nolen(*sv_B);
    cu.order    = SvPV_nolen(*sv_order);
    cu.Gx       = SvPV_nolen(*sv_Gx);
    cu.Gy       = SvPV_nolen(*sv_Gy);
    cu.cofactor = (unsigned long)SvUV(*sv_cofactor);

    if ((err = ecc_set_curve(&cu, key)) != CRYPT_OK) return err;
    if (key->dp.oidlen == 0) _ecc_oid_lookup(key);
    return CRYPT_OK;
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

MODULE = CryptX       PACKAGE = Crypt::Misc

PROTOTYPES: DISABLE

SV *
_radix_to_bin(char *in, int radix)
    CODE:
    {
        STRLEN len;
        unsigned char *out_data;
        mp_int mpi;

        if (in == NULL) XSRETURN_UNDEF;
        if (mp_init(&mpi) != MP_OKAY) XSRETURN_UNDEF;
        if (strlen(in) == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else if (mp_read_radix(&mpi, in, radix) == CRYPT_OK) {
          len = mp_unsigned_bin_size(&mpi);
          if (len == 0) {
            RETVAL = newSVpvn("", 0);
          }
          else {
            RETVAL = NEWSV(0, len); /* avoid zero! */
            SvPOK_only(RETVAL);
            SvCUR_set(RETVAL, len);
            out_data = (unsigned char *)SvPVX(RETVAL);
            if (mp_to_unsigned_bin(&mpi, out_data) != MP_OKAY) {
              SvREFCNT_dec(RETVAL);
              RETVAL = newSVpvn(NULL, 0); /* undef */
            }
          }
        }
        else {
          RETVAL = newSVpvn(NULL, 0); /* undef */
        }
        mp_clear(&mpi);
    }
    OUTPUT:
        RETVAL

SV *
_bin_to_radix(SV *in, int radix)
    CODE:
    {
        STRLEN len;
        unsigned char *in_data;
        char *out_data;
        mp_int mpi, tmp;
        mp_digit d;
        mp_err merr;
        int digits = 0;

        if (!SvPOK(in) || radix < 2 || radix > 64) XSRETURN_UNDEF;
        in_data = (unsigned char *) SvPVbyte(in, len);
        if (mp_init_multi(&mpi, &tmp, NULL) != MP_OKAY) XSRETURN_UNDEF;
        if (len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          if (mp_read_unsigned_bin(&mpi, in_data, (unsigned long)len) == CRYPT_OK) {
            merr = mp_copy(&mpi, &tmp);
            while (merr == MP_OKAY && mp_iszero(&tmp) == MP_NO) {
              merr = mp_div_d(&tmp, (mp_digit)radix, &tmp, &d);
              digits++;
            }
            if (merr != MP_OKAY) {
              RETVAL = newSVpvn(NULL, 0); /* undef */
            }
            else if (digits == 0) {
              RETVAL = newSVpvn("", 0);
            }
            else {
              RETVAL = NEWSV(0, digits + 2); /* +2 for sign and NUL byte */
              SvPOK_only(RETVAL);
              out_data = SvPVX(RETVAL);
              if (mp_toradix(&mpi, out_data, radix) == MP_OKAY) {
                SvCUR_set(RETVAL, strlen(out_data));
              }
              else {
                SvREFCNT_dec(RETVAL);
                RETVAL = newSVpvn(NULL, 0); /* undef */
              }
            }
          }
          else {
            RETVAL = newSVpvn(NULL, 0); /* undef */
          }
        }
        mp_clear_multi(&tmp, &mpi, NULL);
    }
    OUTPUT:
        RETVAL

SV *
encode_b64(SV * in)
    ALIAS:
        encode_b64u = 1
    CODE:
    {
        int rv;
        STRLEN in_len;
        unsigned long out_len;
        unsigned char *in_data;
        char *out_data;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        in_data = (unsigned char *) SvPVbyte(in, in_len);
        if (in_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          out_len = (unsigned long)(4 * ((in_len + 2) / 3) + 1);
          RETVAL = NEWSV(0, out_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          out_data = SvPVX(RETVAL);
          if (ix == 1)
            rv = base64url_encode(in_data, (unsigned long)in_len, out_data, &out_len);
          else
            rv = base64_encode(in_data, (unsigned long)in_len, out_data, &out_len);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            XSRETURN_UNDEF;
          }
          SvCUR_set(RETVAL, out_len);
        }
    }
    OUTPUT:
        RETVAL

SV *
decode_b64(SV * in)
    ALIAS:
        decode_b64u = 1
    CODE:
    {
        int rv;
        STRLEN in_len;
        unsigned long out_len;
        unsigned char *out_data;
        char *in_data;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        in_data = SvPVbyte(in, in_len);
        if (in_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          out_len = (unsigned long)in_len;
          RETVAL = NEWSV(0, out_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          out_data = (unsigned char *)SvPVX(RETVAL);
          if (ix == 1)
            rv = base64url_sane_decode(in_data, (unsigned long)in_len, out_data, &out_len);
          else
            rv = base64_sane_decode(in_data, (unsigned long)in_len, out_data, &out_len);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            XSRETURN_UNDEF;
          }
          SvCUR_set(RETVAL, out_len);
        }
    }
    OUTPUT:
        RETVAL

SV *
encode_b32r(SV *in)
    ALIAS:
        encode_b32b = 1
        encode_b32z = 2
        encode_b32c = 3
    CODE:
    {
        STRLEN in_len;
        unsigned long out_len;
        unsigned char *in_data;
        char *out_data;
        int id = -1, err;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        if (ix == 0) id = BASE32_RFC4648;
        if (ix == 1) id = BASE32_BASE32HEX;
        if (ix == 2) id = BASE32_ZBASE32;
        if (ix == 3) id = BASE32_CROCKFORD;
        if (id == -1) XSRETURN_UNDEF;
        in_data = (unsigned char *) SvPVbyte(in, in_len);
        if (in_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          out_len = (unsigned long)((8 * in_len + 4) / 5 + 1);
          RETVAL = NEWSV(0, out_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          out_data = SvPVX(RETVAL);
          err = base32_encode(in_data, (unsigned long)in_len, out_data, &out_len, id);
          if (err != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            XSRETURN_UNDEF;
          }
          SvCUR_set(RETVAL, out_len);
        }
    }
    OUTPUT:
        RETVAL

SV *
decode_b32r(SV *in)
    ALIAS:
        decode_b32b = 1
        decode_b32z = 2
        decode_b32c = 3
    CODE:
    {
        STRLEN in_len;
        unsigned long out_len;
        unsigned char *out_data;
        char *in_data;
        int id = -1, err;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        if (ix == 0) id = BASE32_RFC4648;
        if (ix == 1) id = BASE32_BASE32HEX;
        if (ix == 2) id = BASE32_ZBASE32;
        if (ix == 3) id = BASE32_CROCKFORD;
        if (id == -1) XSRETURN_UNDEF;
        in_data = SvPVbyte(in, in_len);
        if (in_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          out_len = (unsigned long)in_len;
          RETVAL = NEWSV(0, out_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          out_data = (unsigned char *)SvPVX(RETVAL);
          err = base32_decode(in_data, (unsigned long)in_len, out_data, &out_len, id);
          if (err != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            XSRETURN_UNDEF;
          }
          SvCUR_set(RETVAL, out_len);
        }
    }
    OUTPUT:
        RETVAL

SV *
increment_octets_le(SV * in)
    CODE:
    {
        STRLEN len, i = 0;
        unsigned char *out_data, *in_data;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        in_data = (unsigned char *)SvPVbyte(in, len);
        if (len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          RETVAL = NEWSV(0, len); /* avoid zero! */
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
    }
    OUTPUT:
        RETVAL

SV *
increment_octets_be(SV * in)
    CODE:
    {
        STRLEN len, i = 0;
        unsigned char *out_data, *in_data;

        if (!SvPOK(in)) XSRETURN_UNDEF;
        in_data = (unsigned char *)SvPVbyte(in, len);
        if (len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          RETVAL = NEWSV(0, len); /* avoid zero! */
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
    }
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
INCLUDE: inc/CryptX_Stream_Salsa20.xs.inc
INCLUDE: inc/CryptX_Stream_RC4.xs.inc
INCLUDE: inc/CryptX_Stream_Sober128.xs.inc
INCLUDE: inc/CryptX_Stream_Sosemanuk.xs.inc
INCLUDE: inc/CryptX_Stream_Rabbit.xs.inc

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
INCLUDE: inc/CryptX_PK_Ed25519.xs.inc
INCLUDE: inc/CryptX_PK_X25519.xs.inc

INCLUDE: inc/CryptX_KeyDerivation.xs.inc

INCLUDE: inc/CryptX_BigInt_LTM.xs.inc
