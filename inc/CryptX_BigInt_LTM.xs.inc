MODULE = CryptX         PACKAGE = Math::BigInt::LTM


##############################################################################
# _new()

Math::BigInt::LTM
_new(Class, SV *x)
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    mp_init(RETVAL);
    if ((SvUOK(x) || SvIOK(x)) && (sizeof(UV) <= sizeof(unsigned long) || SvUV(x) == (unsigned long)SvUV(x))) {
      mp_set_int(RETVAL, (unsigned long)SvUV(x));
    }
    else {
      mp_read_radix(RETVAL, SvPV_nolen(x), 10);
    }
  OUTPUT:
    RETVAL

##############################################################################
# _from_bin()

Math::BigInt::LTM
_from_bin(Class, SV *x)
  PREINIT:
    char *str, *start;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    mp_init(RETVAL);
    str = SvPV_nolen(x);
    start = (strlen(str)>2 && str[0] == '0' && str[1] == 'b') ? str+2 : str;
    mp_read_radix(RETVAL, start, 2);
  OUTPUT:
    RETVAL

##############################################################################
# _from_hex()

Math::BigInt::LTM
_from_hex(Class, SV *x)
  PREINIT:
    char *str, *start;
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    mp_init(RETVAL);
    str = SvPV_nolen(x);
    start = (strlen(str)>2 && str[0] == '0' && str[1] == 'x') ? str+2 : str;
    mp_read_radix(RETVAL, start, 16);
  OUTPUT:
    RETVAL

##############################################################################
# _from_oct()

Math::BigInt::LTM
_from_oct(Class, SV *x)
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    mp_init(RETVAL);
    mp_read_radix(RETVAL, SvPV_nolen(x), 8);
  OUTPUT:
    RETVAL

##############################################################################
# _set() - set an already existing object to the given scalar value

void
_set(Class, Math::BigInt::LTM n, SV *x)
  CODE:
    mp_set_int(n, SvIV(x));

##############################################################################
# _zero()

Math::BigInt::LTM
_zero(Class)
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    mp_init(RETVAL);
    mp_set_int(RETVAL, 0);
  OUTPUT:
    RETVAL

##############################################################################
# _one()

Math::BigInt::LTM
_one(Class)
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    mp_init(RETVAL);
    mp_set_int(RETVAL, 1);
  OUTPUT:
    RETVAL

##############################################################################
# _two()

Math::BigInt::LTM
_two(Class)
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    mp_init(RETVAL);
    mp_set_int(RETVAL, 2);
  OUTPUT:
    RETVAL

##############################################################################
# _ten()

Math::BigInt::LTM
_ten(Class)
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    mp_init(RETVAL);
    mp_set_int(RETVAL, 10);
  OUTPUT:
    RETVAL

##############################################################################
# _1ex()

Math::BigInt::LTM
_1ex(Class, int x)
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    mp_init(RETVAL);
    mp_set_int(RETVAL, 10);
    mp_expt_d(RETVAL, x, RETVAL);
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
    int len;
    char *buf;
  CODE:
    if (mp_iszero(n) == MP_YES) {
      RETVAL = newSVpv("0", 0);
    }
    else {
      len = mp_count_bits(n) / 3 + 3; /* decimal_size ~ (binary_size/3 + 1) +1 for sign +1 for NUL-byte */
      Newz(0, buf, len, char);
      mp_toradix_n(n, buf, 10, len);
      RETVAL = newSVpv(buf, 0);
      Safefree(buf);
    }
  OUTPUT:
    RETVAL

##############################################################################
# _len() - return the length of the number in base 10 (costly)

int
_len(Class, Math::BigInt::LTM n)
  PREINIT:
    int len;
    char *buf;
  CODE:
    if (mp_iszero(n) == MP_YES) {
      RETVAL = 1;
    }
    else {
      len = mp_count_bits(n) / 3 + 3; /* decimal_size ~ (binary_size/3 + 1) +1 for sign +1 for NUL-byte */
      Newz(0, buf, len, char);
      mp_toradix_n(n, buf, 10, len);
      RETVAL = strlen(buf);
      Safefree(buf);
    }
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
    int len;
    char *buf;
  CODE:
    if (mp_iszero(n) == MP_YES) {
      RETVAL = 0; /* '0' has no trailing zeros! */
    }
    else {
      len = mp_count_bits(n) / 3 + 3; /* decimal_size ~ (binary_size/3 + 1) +1 for sign +1 for NUL-byte */
      Newz(0, buf, len, char);
      mp_toradix_n(n, buf, 10, len);
      len = strlen(buf);
      RETVAL = 0;
      while (len > 0) {
        if (buf[len-1] != '0') break;
        RETVAL++;
        len--;
      }
      Safefree(buf);
    }
  OUTPUT:
    RETVAL

##############################################################################
# _as_hex() - return ref to hexadecimal string (prefixed with 0x)

SV *
_as_hex(Class, Math::BigInt::LTM n)
  PREINIT:
    int i, len;
    char *buf;
  CODE:
    len = mp_unsigned_bin_size(n) * 2 + 3;
    RETVAL = newSV(len);
    SvPOK_on(RETVAL);
    buf = SvPVX(RETVAL);                /* get ptr to storage */
    *buf++ = '0'; *buf++ = 'x';         /* prepend '0x' */
    mp_tohex(n, buf);
    for (i=0; i<len && buf[i]>0; i++) buf[i] = toLOWER(buf[i]);
    SvCUR_set(RETVAL, strlen(buf)+2);   /* set real length */
  OUTPUT:
    RETVAL

##############################################################################
# _as_bin() - return ref to binary string (prefixed with 0b)

SV *
_as_bin(Class, Math::BigInt::LTM n)
  PREINIT:
    int len;
    char *buf;
  CODE:
    len = mp_unsigned_bin_size(n) * 8 + 3;
    RETVAL = newSV(len);
    SvPOK_on(RETVAL);
    buf = SvPVX(RETVAL);                /* get ptr to storage */
    *buf++ = '0'; *buf++ = 'b';         /* prepend '0b' */
    mp_tobinary(n, buf);
    SvCUR_set(RETVAL, strlen(buf)+2);   /* set real length */
  OUTPUT:
    RETVAL

##############################################################################
# _as_oct() - return ref to octal string (prefixed with 0)

SV *
_as_oct(Class, Math::BigInt::LTM n)
  PREINIT:
    int len;
    char *buf;
  CODE:
    len = mp_unsigned_bin_size(n) * 3 + 3;
    RETVAL = newSV(len);
    SvPOK_on(RETVAL);
    buf = SvPVX(RETVAL);
    *buf++ = '0';                       /* prepend '0' */
    mp_tooctal(n, buf);
    SvCUR_set(RETVAL, strlen(buf)+1);   /* set real length */
  OUTPUT:
    RETVAL

##############################################################################
# _modpow() - ($n ** $exp) % $mod

Math::BigInt::LTM
_modpow(Class, Math::BigInt::LTM n, Math::BigInt::LTM exp, Math::BigInt::LTM mod)
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    mp_init(RETVAL);
    if (mp_cmp_d(mod, 1) == MP_EQ) {
      mp_set_int(RETVAL, 0);
    }
    else {
      mp_exptmod(n, exp, mod, RETVAL);
    }
  OUTPUT:
    RETVAL

##############################################################################
# _modinv() - compute the inverse of x % y

void
_modinv(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PREINIT:
    int rc;
    SV* s;
    mp_int* RETVAL;
  PPCODE:
    Newz(0, RETVAL, 1, mp_int);
    mp_init(RETVAL);
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

##############################################################################
# _add() - add $y to $x in place

void
_add(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PPCODE:
    mp_add(x, y, x);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _inc() - modify x inline by doing x++

void
_inc(Class, Math::BigInt::LTM x)
  PPCODE:
    mp_add_d(x, 1, x);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _dec() - modify x inline by doing x--

void
_dec(Class, Math::BigInt::LTM x)
  PPCODE:
    mp_sub_d(x, 1, x);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _sub() - $x - $y
# $x is always larger than $y! So overflow/underflow can not happen here.

void
_sub(Class, Math::BigInt::LTM x, Math::BigInt::LTM y, ...)
  PPCODE:
    if ( items == 4 && SvTRUE(ST(3)) ) {
      /* y -= x */
      mp_sub(x, y, y);
      XPUSHs(ST(2)); /* y */
    }
    else {
      /* x -= y */
      mp_sub(x, y, x);
      XPUSHs(ST(1)); /* x */
    }

##############################################################################
# _rsft()

void
_rsft(Class, Math::BigInt::LTM x, Math::BigInt::LTM y, unsigned long base_int)
  PREINIT:
    mp_int*  BASE;
  PPCODE:
    Newz(0, BASE, 1, mp_int);
    mp_init_set_int(BASE, base_int);
    mp_expt_d(BASE, mp_get_long(y), BASE);
    mp_div(x, BASE, x, NULL);
    mp_clear(BASE);
    Safefree(BASE);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _lsft()

void
_lsft(Class, Math::BigInt::LTM x, Math::BigInt::LTM y, unsigned long base_int)
  PREINIT:
    mp_int*  BASE;
  PPCODE:
    Newz(0, BASE, 1, mp_int);
    mp_init_set_int(BASE, base_int);
    mp_expt_d(BASE, mp_get_long(y), BASE);
    mp_mul(x, BASE, x);
    mp_clear(BASE);
    Safefree(BASE);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _mul()

void
_mul(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PPCODE:
    mp_mul(x, y, x);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _div(): x /= y or (x,rem) = x / y

void
_div(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PREINIT:
    mp_int * rem;
  PPCODE:
    if (GIMME_V == G_ARRAY) {
      Newz(0, rem, 1, mp_int);
      mp_init(rem);
      mp_div(x, y, x, rem);
      EXTEND(SP, 2);
      PUSHs(ST(1)); /* x */
      PUSHs(sv_2mortal(sv_from_mpi(rem)));
    }
    else {
      mp_div(x, y, x, NULL);
      XPUSHs(ST(1)); /* x */
    }

##############################################################################
# _mod() - x %= y

void
_mod(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PPCODE:
    mp_mod(x, y, x);
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
  PPCODE:
    mp_expt_d(x, mp_get_long(y), x);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _gcd() - gcd(m,n)

Math::BigInt::LTM
_gcd(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    mp_init(RETVAL);
    mp_gcd(x, y, RETVAL);
  OUTPUT:
    RETVAL

##############################################################################
# _and() - m &= n

void
_and(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PPCODE:
    mp_and(x, y, x);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _xor() - m =^ n

void
_xor(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PPCODE:
    mp_xor(x, y, x);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _or() - m =| n

void
_or(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PPCODE:
    mp_or(x, y, x);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _copy()

Math::BigInt::LTM
_copy(Class, Math::BigInt::LTM m)
  CODE:
    Newz(0, RETVAL, 1, mp_int);
    mp_init(RETVAL);
    mp_copy(m, RETVAL);
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
  PPCODE:
    mp_sqrt(x, x);
    XPUSHs(ST(1)); /* x */

##############################################################################
# _root() - integer roots

void
_root(Class, Math::BigInt::LTM x, Math::BigInt::LTM y)
  PPCODE:
    mp_n_root(x, mp_get_long(y), x);
    XPUSHs(ST(1)); /* x */

##############################################################################
# Storable hooks

void
STORABLE_thaw(blank_obj, cloning, serialized, ...)
    SV *blank_obj
    SV *cloning = NO_INIT
    SV *serialized
  PREINIT:
    SV *target;
    mp_int *mpi;
  PPCODE:
    PERL_UNUSED_VAR(cloning);
    if (SvROK(blank_obj) && sv_isa(blank_obj, "Math::BigInt::LTM")) {
        Newz(0, mpi, 1, mp_int);
        mp_init(mpi);
        mp_read_radix(mpi, SvPV_nolen(serialized), 10);
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
      mp_toradix_n(self, buf, 10, len);
      RETVAL = newSVpv(buf, 0);
      Safefree(buf);
    }
OUTPUT:
    RETVAL
