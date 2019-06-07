MODULE = CryptX         PACKAGE = Math::BigInt::LTM

PROTOTYPES: DISABLE

##############################################################################
# _new()

Math::BigInt::LTM
_new(Class, SV *x)
  PREINIT:
    mp_err merr;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    merr = mp_init(RETVAL);
#ifdef BN_MP_SET_INT_C
    if ((SvUOK(x) || SvIOK(x)) && (sizeof(UV) <= sizeof(unsigned long) || SvUV(x) == (unsigned long)SvUV(x))) {
      mp_set_int(RETVAL, (unsigned long)SvUV(x));
    }
#elif IVSIZE == 8
    if (SvUOK(x)) {
      mp_set_u64(RETVAL, (unsigned long long)SvUV(x));
    }
    else if (SvIOK(x)) {
      mp_set_i64(RETVAL, (long long)SvIV(x));
    }
#else
    if (SvUOK(x)) {
      mp_set_u32(RETVAL, (unsigned int)SvUV(x));
    }
    else if (SvIOK(x)) {
      mp_set_i32(RETVAL, (int)SvIV(x));
    }
#endif
    else {
      /* fallback - read the decimal number from string */
      merr = mp_read_radix(RETVAL, SvPV_nolen(x), 10);
    }
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _from_bin()

Math::BigInt::LTM
_from_bin(Class, SV *x)
  PREINIT:
    mp_err merr;
    char *str, *start;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    merr = mp_init(RETVAL);
    str = SvPV_nolen(x);
    start = (strlen(str)>2 && str[0] == '0' && str[1] == 'b') ? str+2 : str;
    merr = mp_read_radix(RETVAL, start, 2);
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _from_hex()

Math::BigInt::LTM
_from_hex(Class, SV *x)
  PREINIT:
    mp_err merr;
    char *str, *start;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    merr = mp_init(RETVAL);
    str = SvPV_nolen(x);
    start = (strlen(str)>2 && str[0] == '0' && str[1] == 'x') ? str+2 : str;
    merr = mp_read_radix(RETVAL, start, 16);
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _from_oct()

Math::BigInt::LTM
_from_oct(Class, SV *x)
  PREINIT:
    mp_err merr;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    merr = mp_init(RETVAL);
    merr = mp_read_radix(RETVAL, SvPV_nolen(x), 8);
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _from_base()

Math::BigInt::LTM
_from_base(Class, SV *x, int base)
  PREINIT:
    mp_err merr;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    merr = mp_init(RETVAL);
    merr = mp_read_radix(RETVAL, SvPV_nolen(x), base);
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _from_bytes()

Math::BigInt::LTM
_from_bytes(Class, SV *x)
  PREINIT:
    mp_err merr;
    STRLEN buf_len;
    unsigned char *buf_ptr;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    merr = mp_init(RETVAL);
    buf_ptr = (unsigned char *)SvPVbyte(x, buf_len);
    merr = mp_read_unsigned_bin(RETVAL, buf_ptr, buf_len);
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _set() - set an already existing object to the given scalar value

void
_set(Class, Math::BigInt::LTM n, SV *x)
  PREINIT:
    mp_err merr;
  CODE:
#ifdef BN_MP_SET_INT_C
    if ((SvUOK(x) || SvIOK(x)) && (sizeof(UV) <= sizeof(unsigned long) || SvUV(x) == (unsigned long)SvUV(x))) {
      mp_set_int(n, (unsigned long)SvIV(x));
    }
#elif IVSIZE == 8
    if (SvUOK(x)) {
      mp_set_u64(n, (unsigned long long)SvUV(x));
    }
    else if (SvIOK(x)) {
      mp_set_i64(n, (long long)SvIV(x));
    }
#else
    if (SvUOK(x)) {
      mp_set_u32(n, (unsigned int)SvUV(x));
    }
    else if (SvIOK(x)) {
      mp_set_i32(n, (int)SvIV(x));
    }
#endif
    else {
      /* fallback - read the decimal number from string */
      merr = mp_read_radix(n, SvPV_nolen(x), 10);
      PERL_UNUSED_VAR(merr);
    }

##############################################################################
# _zero()

Math::BigInt::LTM
_zero(Class)
  PREINIT:
    mp_err merr;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    merr = mp_init(RETVAL);
    mp_zero(RETVAL);
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _one()

Math::BigInt::LTM
_one(Class)
  PREINIT:
    mp_err merr;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    merr = mp_init(RETVAL);
#ifdef BN_MP_SET_INT_C
    mp_set_int(RETVAL, 1);
#else
    mp_set_u32(RETVAL, 1);
#endif
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _two()

Math::BigInt::LTM
_two(Class)
  PREINIT:
    mp_err merr;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    merr = mp_init(RETVAL);
#ifdef BN_MP_SET_INT_C
    mp_set_int(RETVAL, 2);
#else
    mp_set_u32(RETVAL, 2);
#endif
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _ten()

Math::BigInt::LTM
_ten(Class)
  PREINIT:
    mp_err merr;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    merr = mp_init(RETVAL);
#ifdef BN_MP_SET_INT_C
    mp_set_int(RETVAL, 10);
#else
    mp_set_u32(RETVAL, 10);
#endif
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _1ex()

Math::BigInt::LTM
_1ex(Class, int x)
  PREINIT:
    mp_err merr;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    merr = mp_init(RETVAL);
#ifdef BN_MP_SET_INT_C
    mp_set_int(RETVAL, 10);
#else
    mp_set_u32(RETVAL, 10);
#endif
    merr = mp_expt_d(RETVAL, x, RETVAL);
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# DESTROY() - free memory of a GMP number

void
DESTROY(Math::BigInt::LTM n)
  PPCODE:
    if (n) {
      mp_clear(n);
      Safefree(n);
    }

##############################################################################
# _str() - return string so that atof() and atoi() can use it

SV *
_str(Class, Math::BigInt::LTM n)
  PREINIT:
    mp_err merr;
    int len;
    char *buf;
  CODE:
    if (mp_iszero(n) == MP_YES) {
      RETVAL = newSVpv("0", 0);
    }
    else {
      len = mp_count_bits(n) / 3 + 3; /* decimal_size ~ (binary_size/3 + 1) +1 for sign +1 for NUL-byte */
      Newz(0, buf, len, char);
      merr = mp_toradix_n(n, buf, 10, len);
      RETVAL = newSVpv(buf, 0);
      Safefree(buf);
    }
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _len() - return the length of the number in base 10 (costly)

int
_len(Class, Math::BigInt::LTM n)
  PREINIT:
    mp_err merr;
    int len;
    char *buf;
  CODE:
    if (mp_iszero(n) == MP_YES) {
      RETVAL = 1;
    }
    else {
      len = mp_count_bits(n) / 3 + 3; /* decimal_size ~ (binary_size/3 + 1) +1 for sign +1 for NUL-byte */
      Newz(0, buf, len, char);
      merr = mp_toradix_n(n, buf, 10, len);
      RETVAL = (int)strlen(buf);
      Safefree(buf);
    }
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _alen() - return the approx. length of the number in base 10 (fast)
# _alen() might underestimate, but never overestimate the true value

int
_alen(Class, Math::BigInt::LTM n)
  PREINIT:
    int bits;
  CODE:
    bits = mp_count_bits(n);
    /* alen = round(bits * log(2) / log(10)) */
    RETVAL = (bits < 5) ? 1 : (int)(bits * 0.301029995663 + 0.499999999999);
    /* less accurate approximation, but without floating-point calculations
       RETVAL = (bits < 5) ? 1 : bits / 4 + bits / 32 + bits / 64 + bits / 256;
       RETVAL = (bits < 5) ? 1 : bits / 4;
    */
  OUTPUT:
    RETVAL

##############################################################################
# _zeros() - return number of trailing zeros (in decimal form)

int
_zeros(Class, Math::BigInt::LTM n)
  PREINIT:
    mp_err merr;
    int len;
    char *buf;
  CODE:
    if (mp_iszero(n) == MP_YES) {
      RETVAL = 0; /* '0' has no trailing zeros! */
    }
    else {
      len = mp_count_bits(n) / 3 + 3; /* decimal_size ~ (binary_size/3 + 1) +1 for sign +1 for NUL-byte */
      Newz(0, buf, len, char);
      merr = mp_toradix_n(n, buf, 10, len);
      len = (int)strlen(buf);
      RETVAL = 0;
      while (len > 0) {
        if (buf[len-1] != '0') break;
        RETVAL++;
        len--;
      }
      Safefree(buf);
    }
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _to_hex() - return ref to hexadecimal string (no prefix)

SV *
_to_hex(Class, Math::BigInt::LTM n)
  PREINIT:
    mp_err merr;
    int i, len;
    char *buf;
  CODE:
    len = mp_unsigned_bin_size(n) * 2 + 1;
    RETVAL = newSV(len);
    SvPOK_on(RETVAL);
    buf = SvPVX(RETVAL);
    merr = mp_toradix(n, buf, 16); /* to hex */
    for (i=0; i<len && buf[i]>0; i++) buf[i] = toLOWER(buf[i]);
    SvCUR_set(RETVAL, strlen(buf));
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _to_bin() - return ref to binary string (no prefix)

SV *
_to_bin(Class, Math::BigInt::LTM n)
  PREINIT:
    mp_err merr;
    int len;
    char *buf;
  CODE:
    len = mp_unsigned_bin_size(n) * 8 + 1;
    RETVAL = newSV(len);
    SvPOK_on(RETVAL);
    buf = SvPVX(RETVAL);
    merr = mp_toradix(n, buf, 2); /* to binary */
    SvCUR_set(RETVAL, strlen(buf));
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _to_oct() - return ref to octal string (no prefix)

SV *
_to_oct(Class, Math::BigInt::LTM n)
  PREINIT:
    mp_err merr;
    int len;
    char *buf;
  CODE:
    len = mp_unsigned_bin_size(n) * 3 + 1;
    RETVAL = newSV(len);
    SvPOK_on(RETVAL);
    buf = SvPVX(RETVAL);
    merr = mp_toradix(n, buf, 8); /* to octal */
    SvCUR_set(RETVAL, strlen(buf));
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _to_base() - raw bytes

SV *
_to_base(Class, Math::BigInt::LTM n, int base)
  PREINIT:
    mp_err merr;
    int len;
    char *buf;
  CODE:
    len = mp_unsigned_bin_size(n) * 8; /* the worst case for base == 2 */
    RETVAL = newSV(len + 1);
    SvPOK_on(RETVAL);
    buf = SvPVX(RETVAL);
    if (len > 0) {
      merr = mp_toradix_n(n, buf, base, len);
      SvCUR_set(RETVAL, strlen(buf));
    }
    else {
      buf[0] = '0';
      SvCUR_set(RETVAL, 1);
    }
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _to_bytes() - raw bytes
# _as_bytes() - raw bytes

SV *
_to_bytes(Class, Math::BigInt::LTM n)
  ALIAS:
    _as_bytes = 1
  PREINIT:
    mp_err merr;
    int len;
    unsigned char *buf;
  CODE:
    PERL_UNUSED_VAR(ix);
    len = mp_unsigned_bin_size(n);
    RETVAL = newSV(len + 1);
    SvPOK_on(RETVAL);
    buf = (unsigned char*)SvPVX(RETVAL);
    if (len > 0) {
      merr = mp_to_unsigned_bin(n, buf);
      SvCUR_set(RETVAL, len);
    }
    else {
      buf[0] = 0;
      SvCUR_set(RETVAL, 1);
    }
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _modpow() - ($n ** $exp) % $mod

Math::BigInt::LTM
_modpow(Class, Math::BigInt::LTM n, Math::BigInt::LTM exp, Math::BigInt::LTM mod)
  PREINIT:
    mp_err merr;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    merr = mp_init(RETVAL);
    if (mp_cmp_d(mod, 1) == MP_EQ) {
      mp_zero(RETVAL);
    }
    else {
      merr = mp_exptmod(n, exp, mod, RETVAL);
    }
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _modinv() - compute the inverse of x % y

void
_modinv(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PREINIT:
    mp_err merr;
    int rc;
    SV* s;
    mp_int* RETVAL;
  PPCODE:
    Newz(0, RETVAL, 1, mp_int);
    merr = mp_init(RETVAL);
    rc = mp_invmod(x, y, RETVAL);
    EXTEND(SP, 2);      /* we return two values */
    if (rc != MP_OKAY) {
      /* Inverse doesn't exist. Return both values undefined. */
      PUSHs(&PL_sv_undef);
      PUSHs(&PL_sv_undef);
    }
    else {
      /* Inverse exists. When the modulus to mp_invert() is positive,
       * the returned value is also positive. */
      PUSHs(sv_2mortal(sv_from_mpi(RETVAL)));
      s = sv_newmortal();
      sv_setpvn(s, "+", 1);
      PUSHs(s);
    }
    PERL_UNUSED_VAR(merr);

##############################################################################
# _add() - add $y to $x in place

void
_add(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PREINIT:
    mp_err merr;
  PPCODE:
    merr = mp_add(x, y, x);
    PERL_UNUSED_VAR(merr);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _inc() - modify x inline by doing x++

void
_inc(Class, Math::BigInt::LTM x)
  PREINIT:
    mp_err merr;
  PPCODE:
    merr = mp_add_d(x, 1, x);
    PERL_UNUSED_VAR(merr);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _dec() - modify x inline by doing x--

void
_dec(Class, Math::BigInt::LTM x)
  PREINIT:
    mp_err merr;
  PPCODE:
    merr = mp_sub_d(x, 1, x);
    PERL_UNUSED_VAR(merr);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _sub() - $x - $y
# $x is always larger than $y! So overflow/underflow can not happen here.

void
_sub(Class, Math::BigInt::LTM x, Math::BigInt::LTM y, ...)
  PREINIT:
    mp_err merr;
  PPCODE:
    if ( items == 4 && SvTRUE(ST(3)) ) {
      /* y -= x */
      merr = mp_sub(x, y, y);
      XPUSHs(ST(2)); /* y */
    }
    else {
      /* x -= y */
      merr = mp_sub(x, y, x);
      XPUSHs(ST(1)); /* x */
    }
    PERL_UNUSED_VAR(merr);

##############################################################################
# _rsft()

void
_rsft(Class, Math::BigInt::LTM x, Math::BigInt::LTM y, unsigned long base_int)
  PREINIT:
    mp_err merr;
    mp_int*  BASE;
  PPCODE:
    Newz(0, BASE, 1, mp_int);
    merr = mp_init(BASE);
#ifdef BN_MP_SET_INT_C
    mp_set_int(BASE, base_int);
#else
    mp_set_ul(BASE, base_int);
#endif
#ifdef BN_MP_GET_LONG_C
    merr = mp_expt_d(BASE, mp_get_long(y), BASE);
#else
    merr = mp_expt_d(BASE, mp_get_ul(y), BASE);
#endif
    merr = mp_div(x, BASE, x, NULL);
    PERL_UNUSED_VAR(merr);
    mp_clear(BASE);
    Safefree(BASE);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _lsft()

void
_lsft(Class, Math::BigInt::LTM x, Math::BigInt::LTM y, unsigned long base_int)
  PREINIT:
    mp_err merr;
    mp_int*  BASE;
  PPCODE:
    Newz(0, BASE, 1, mp_int);
    merr = mp_init(BASE);
#ifdef BN_MP_SET_INT_C
    mp_set_int(BASE, base_int);
#else
    mp_set_ul(BASE, base_int);
#endif
#ifdef BN_MP_GET_LONG_C
    merr = mp_expt_d(BASE, mp_get_long(y), BASE);
#else
    merr = mp_expt_d(BASE, mp_get_ul(y), BASE);
#endif
    merr = mp_mul(x, BASE, x);
    PERL_UNUSED_VAR(merr);
    mp_clear(BASE);
    Safefree(BASE);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _mul()

void
_mul(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PREINIT:
    mp_err merr;
  PPCODE:
    merr = mp_mul(x, y, x);
    PERL_UNUSED_VAR(merr);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _div(): x /= y or (x,rem) = x / y

void
_div(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PREINIT:
    mp_err merr;
    mp_int * rem;
  PPCODE:
    if (GIMME_V == G_ARRAY) {
      Newz(0, rem, 1, mp_int);
      merr = mp_init(rem);
      merr = mp_div(x, y, x, rem);
      EXTEND(SP, 2);
      PUSHs(ST(1)); /* x */
      PUSHs(sv_2mortal(sv_from_mpi(rem)));
    }
    else {
      merr = mp_div(x, y, x, NULL);
      XPUSHs(ST(1)); /* x */
    }
    PERL_UNUSED_VAR(merr);

##############################################################################
# _mod() - x %= y

void
_mod(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PREINIT:
    mp_err merr;
  PPCODE:
    merr = mp_mod(x, y, x);
    PERL_UNUSED_VAR(merr);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _acmp() - cmp two numbers

int
_acmp(Class, Math::BigInt::LTM m, Math::BigInt::LTM n)
  CODE:
    RETVAL = mp_cmp(m, n);
    if ( RETVAL < 0) RETVAL = -1;
    if ( RETVAL > 0) RETVAL =  1;
  OUTPUT:
    RETVAL

##############################################################################
# _is_zero()

int
_is_zero(Class, Math::BigInt::LTM x)
  CODE:
    RETVAL = (mp_iszero(x) == MP_YES) ? 1 : 0;
  OUTPUT:
    RETVAL

##############################################################################
# _is_one()

int
_is_one(Class, Math::BigInt::LTM x)
  CODE:
    RETVAL = (mp_cmp_d(x, 1) == MP_EQ) ? 1 : 0;
  OUTPUT:
    RETVAL

##############################################################################
# _is_two()

int
_is_two(Class, Math::BigInt::LTM x)
  CODE:
    RETVAL = (mp_cmp_d(x, 2) == MP_EQ) ? 1 : 0;
  OUTPUT:
    RETVAL

##############################################################################
# _is_ten()

int
_is_ten(Class, Math::BigInt::LTM x)
  CODE:
    RETVAL = (mp_cmp_d(x, 10) == MP_EQ) ? 1 : 0;
  OUTPUT:
    RETVAL

##############################################################################
# _pow() - x **= y

void
_pow(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PREINIT:
    mp_err merr;
  PPCODE:
#ifdef BN_MP_GET_LONG_C
    merr = mp_expt_d(x, mp_get_long(y), x);
#else
    merr = mp_expt_d(x, mp_get_ul(y), x);
#endif
    PERL_UNUSED_VAR(merr);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _gcd() - gcd(m,n)

Math::BigInt::LTM
_gcd(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PREINIT:
    mp_err merr;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    merr = mp_init(RETVAL);
    merr = mp_gcd(x, y, RETVAL);
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _and() - m &= n

void
_and(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PREINIT:
    mp_err merr;
  PPCODE:
    merr = mp_and(x, y, x);
    PERL_UNUSED_VAR(merr);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _xor() - m =^ n

void
_xor(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PREINIT:
    mp_err merr;
  PPCODE:
    merr = mp_xor(x, y, x);
    PERL_UNUSED_VAR(merr);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _or() - m =| n

void
_or(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PREINIT:
    mp_err merr;
  PPCODE:
    merr = mp_or(x, y, x);
    PERL_UNUSED_VAR(merr);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _copy()

Math::BigInt::LTM
_copy(Class, Math::BigInt::LTM m)
  PREINIT:
    mp_err merr;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    merr = mp_init(RETVAL);
    merr = mp_copy(m, RETVAL);
    PERL_UNUSED_VAR(merr);
  OUTPUT:
    RETVAL

##############################################################################
# _is_odd() - test for number being odd

int
_is_odd(Class, Math::BigInt::LTM n)
  CODE:
    RETVAL = (mp_isodd(n) == MP_YES) ? 1 : 0;
  OUTPUT:
    RETVAL

##############################################################################
# _is_even() - test for number being even

int
_is_even(Class, Math::BigInt::LTM n)
  CODE:
    RETVAL = (mp_iseven(n) == MP_YES || mp_iszero(n) == MP_YES) ? 1 : 0;
  OUTPUT:
    RETVAL

##############################################################################
# _sqrt() - square root

void
_sqrt(Class, Math::BigInt::LTM x)
  PREINIT:
    mp_err merr;
  PPCODE:
    merr = mp_sqrt(x, x);
    PERL_UNUSED_VAR(merr);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _root() - integer roots

void
_root(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PREINIT:
    mp_err merr;
  PPCODE:
#ifdef BN_MP_GET_LONG_C
    merr = mp_n_root(x, mp_get_long(y), x);
#else
    merr = mp_n_root(x, mp_get_ul(y), x);
#endif
    PERL_UNUSED_VAR(merr);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _lcm() - least common multiple
void
_lcm(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PREINIT:
    mp_err merr;
  PPCODE:
    merr = mp_lcm(x, y, x) ;
    PERL_UNUSED_VAR(merr);
    XPUSHs(ST(1)); /* x */

##############################################################################
# Storable hooks

void
STORABLE_thaw(blank_obj, cloning, serialized, ...)
    SV *blank_obj
    SV *cloning = NO_INIT
    SV *serialized
  PREINIT:
    mp_err merr;
    SV *target;
    mp_int *mpi;
  PPCODE:
    PERL_UNUSED_VAR(cloning);
    if (SvROK(blank_obj) && sv_isa(blank_obj, "Math::BigInt::LTM")) {
        Newz(0, mpi, 1, mp_int);
        merr = mp_init(mpi);
        merr = mp_read_radix(mpi, SvPV_nolen(serialized), 10);
        PERL_UNUSED_VAR(merr);
        target = SvRV(blank_obj);
        SvIV_set(target, PTR2IV(mpi));
        SvIOK_on(target);
        PUSHs(target);
        XSRETURN(1);
    }
    else
        croak("Bad object for Math::BigInt::LTM::STORABLE_thaw call");

SV *
STORABLE_freeze(self, cloning = NULL)
    Math::BigInt::LTM self
    SV *cloning = NO_INIT
  PREINIT:
    mp_err merr;
    unsigned long len;
    char *buf;
  CODE:
    PERL_UNUSED_VAR(cloning);
    if (mp_iszero(self) == MP_YES) {
      RETVAL = newSVpv("0", 0);
    }
    else {
      len = mp_count_bits(self) / 3 + 3; /* decimal_size ~ (binary_size/3 + 1) +1 for sign +1 for NUL-byte */
      Newz(0, buf, len, char);
      merr = mp_toradix_n(self, buf, 10, len);
      PERL_UNUSED_VAR(merr);
      RETVAL = newSVpv(buf, 0);
      Safefree(buf);
    }
OUTPUT:
    RETVAL
