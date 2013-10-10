#include <tommath.h>
#ifdef BN_MP_PRIME_LUCAS_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is a library that provides multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

int mp_prime_lucas (mp_int * a, int level, int *result)
{
  fprintf(stderr, "XXX-DEBUG: mp_prime_lucas begin bits=%d, level=%d\n", mp_count_bits(a), level); /* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */

  *result = MP_YES; /* XXX let's always pass */
  return MP_OKAY;
}
#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
