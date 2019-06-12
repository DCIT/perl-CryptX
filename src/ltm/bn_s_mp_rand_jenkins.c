#include "tommath_private.h"
#ifdef BN_S_MP_RAND_JENKINS_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Bob Jenkins' http://burtleburtle.net/bob/rand/smallprng.html */
/* Chosen for speed and a good "mix" */
typedef struct {
   unsigned long long a;
   unsigned long long b;
   unsigned long long c;
   unsigned long long d;
} ranctx;

static ranctx jenkins_x;

#define rot(x,k) (((x)<<(k))|((x)>>(64-(k))))
static unsigned long long s_rand_jenkins_val(void)
{
   unsigned long long e = jenkins_x.a - rot(jenkins_x.b, 7);
   jenkins_x.a = jenkins_x.b ^ rot(jenkins_x.c, 13);
   jenkins_x.b = jenkins_x.c + rot(jenkins_x.d, 37);
   jenkins_x.c = jenkins_x.d + e;
   jenkins_x.d = e + jenkins_x.a;
   return jenkins_x.d;
}

void s_mp_rand_jenkins_init(unsigned long long seed)
{
   unsigned long long i;
   jenkins_x.a = 0xf1ea5eedULL;
   jenkins_x.b = jenkins_x.c = jenkins_x.d = seed;
   for (i = 0uLL; i < 20uLL; ++i) {
      (void)s_rand_jenkins_val();
   }
}

mp_err s_mp_rand_jenkins(void *p, size_t n)
{
   char *q = (char *)p;
   while (n > 0u) {
      int i;
      unsigned long long x = s_rand_jenkins_val();
      for (i = 0; (i < 8) && (n > 0u); ++i, --n) {
         *q++ = (char)(x & 0xFFuLL);
         x >>= 8;
      }
   }
   return MP_OKAY;
}

#endif
