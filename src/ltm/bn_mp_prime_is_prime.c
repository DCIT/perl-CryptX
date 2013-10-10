#include <tommath.h>
#ifdef BN_MP_PRIME_IS_PRIME_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is a library that provides multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
 
 /* ideas from Dana Jacobsen's 
  * https://github.com/danaj/Math-Prime-Util-GMP
  */

int mp_prime_is_prime_ex(mp_int * a, int t, int *result, ltm_prime_callback cb, void *dat)
{
  mp_int b;
  int ix, err, res, abits, atests;

  /* default */
  *result = MP_NO;

  /* test if a is equal to any of the first N primes */
  for (ix = 0; ix < PRIME_SIZE; ix++) {
      if (mp_cmp_d(a, ltm_prime_tab[ix]) == MP_EQ)                      { *result = MP_YES; return MP_OKAY; }
  }

  /* try division by first N primes */
  err = mp_prime_is_divisible(a, &res);
  if (err != MP_OKAY)                                                   { return err; }
  if (res == MP_YES)                                                    { return MP_OKAY; }

  /* if a < N-th-prime*N-th-prime then it is composite */
  ix = ltm_prime_tab[PRIME_SIZE-1] * ltm_prime_tab[PRIME_SIZE-1];
  if (mp_cmp_d(a, ix) == MP_EQ)                                         { return MP_OKAY; }

  /* init b */
  if ((err = mp_init(&b)) != MP_OKAY)                                   { return err; }

  /* Miller Rabin with base 2 */
  mp_set(&b, 2);
  err = mp_prime_miller_rabin(a, &b, &res);
  if (err != MP_OKAY)                                                   { goto LBL_B; }
  if (res != MP_YES)                                                    { goto LBL_B; }

  /* Extra-Strong Lucas test */
  err = mp_prime_lucas(a, 2, &res);
  if (err != MP_OKAY)                                                   { goto LBL_B; }
  if (res != MP_YES)                                                    { goto LBL_B; }

  /* BPSW is deterministic below 2^64 */
  if (mp_count_bits(a) <= 64)                                           { *result = MP_YES; return MP_OKAY; }

  if (cb && dat) {
    /* Miller Rabin with N random bases */
    if (t > 0) {
      atests = t;
    }
    else {
      abits = mp_count_bits(a);
      if      (abits <  80) atests = 5;
      else if (abits < 105) atests = 4;
      else if (abits < 160) atests = 3;
      else if (abits < 413) atests = 2;
      else                  atests = 1;
    }
    err = mp_prime_miller_rabin_random(a, atests, &res, cb, dat);
    if (err != MP_OKAY)                                                 { goto LBL_B; }
    if (res != MP_YES)                                                  { goto LBL_B; }
  }
  else {
    /* Miller Rabin with first N primes */
    if (t > 0) {
      atests = t;
    }
    else {
      abits = mp_count_bits(a);
      atests = mp_prime_rabin_miller_trials(abits);
    }
    for (ix = 1; ix < atests; ix++) { /* skip ltm_prime_tab[0] (==2) as it was already tested) */
      mp_set(&b, ltm_prime_tab[ix]);
      if ((err = mp_prime_miller_rabin(a, &b, &res)) != MP_OKAY)          { goto LBL_B; }
      if (res == MP_NO)                                                   { goto LBL_B; }
    }
  }

  /* passed all tests */
  *result = MP_YES;
  err = MP_OKAY;

LBL_B:
  mp_clear(&b);
  return err;
}

int mp_prime_is_prime(mp_int * a, int t, int *result)
{
  return mp_prime_is_prime_ex(a, t, result, NULL, NULL);
}
#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
