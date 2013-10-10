#include <tommath.h>
#ifdef BN_MP_PRIME_MILLER_RABIN_RANDOM_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is a library that provides multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

int mp_prime_miller_rabin_random(mp_int *a, int t, int *result, ltm_prime_callback cb, void *dat)
{
  mp_int b, c;
  int res, err, bsize, trials;
  unsigned char *tmp;

  fprintf(stderr, "XXX-DEBUG: mp_prime_miller_rabin_random begin bits=%d, t=%d\n", mp_count_bits(a), t); /* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */

  /* default */
  *result = MP_NO;

  /* tests should be >0 */
  if (t <= 0)                                                           { return MP_VAL; }

  /* calculate the byte size */
  bsize = mp_unsigned_bin_size(a);

  /* we need a buffer of bsize bytes */
  tmp = OPT_CAST(unsigned char) XMALLOC(bsize);
  if (tmp == NULL)                                                      { return MP_MEM; }

  /* initialize b */
  if ((err = mp_init_multi(&b, &c, NULL)) != MP_OKAY)                   { return err; }

  trials = 0;
  do {
    /* read the bytes */
    if (cb(tmp, bsize, dat) != bsize)                                   { err = MP_VAL; goto LBL_BC; }

    /* read it in */
    if ((err = mp_read_unsigned_bin(&b, tmp, bsize)) != MP_OKAY)        { goto LBL_BC; }

    /* test if b is in [2, a-2] */
    mp_add_d(&b, 1, &c); /* c = b + 1 */
    if (mp_cmp_d(&c, 2) != MP_GT && mp_cmp(&c, a) != MP_LT)             continue;

    /* do Miller Rabin */
    if ((err = mp_prime_miller_rabin(a, &b, &res)) != MP_OKAY)          { goto LBL_BC; }
    if (res == MP_NO)                                                   { err = MP_OKAY; goto LBL_BC; }
    trials++;
  } while (++trials < t);

  /* passed the test */
  *result = MP_YES;
  err = MP_OKAY;

LBL_BC:
  mp_clear_multi(&b, &c, NULL);
  return err;
}
#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
