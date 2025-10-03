/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

int pk_oid_str_to_num(const char *OID, unsigned long *oid, unsigned long *oidlen)
{
   unsigned long i, j, limit, oid_j;

   LTC_ARGCHK(oidlen != NULL);

   limit = *oidlen;
   *oidlen = 0; /* make sure that we return zero oidlen on error */
   if (oid != NULL) {
      XMEMSET(oid, 0, sizeof(*oid) * limit);
   }
   if (OID == NULL) return CRYPT_OK;
   if (OID[0] == '\0') return CRYPT_OK;

   for (i = 0, j = 0; OID[i] != '\0'; i++) {
      if (OID[i] == '.') {
         if (++j >= limit) continue;
      }
      else if ((OID[i] >= '0') && (OID[i] <= '9')) {
         if ((j >= limit) || (oid == NULL)) continue;
         oid_j = oid[j];
         oid[j] = oid[j] * 10 + (OID[i] - '0');
         if (oid[j] < oid_j) return CRYPT_OVERFLOW;
      }
      else {
         return CRYPT_ERROR;
      }
   }
   if (j == 0) return CRYPT_ERROR;
   *oidlen = j + 1;
   if (j >= limit || oid == NULL) {
      return CRYPT_BUFFER_OVERFLOW;
   }
   return CRYPT_OK;
}

typedef struct num_to_str {
   int err;
   char *wr;
   unsigned long max_len, res_len;
} num_to_str;

static LTC_INLINE void s_wr(char c, num_to_str *w)
{
   if (w->res_len == ULONG_MAX) {
      w->err = CRYPT_OVERFLOW;
      return;
   }
   w->res_len++;
   if (w->res_len > w->max_len) w->wr = NULL;
   if (w->wr) w->wr[w->max_len - w->res_len] = c;
}

int pk_oid_num_to_str(const unsigned long *oid, unsigned long oidlen, char *OID, unsigned long *outlen)
{
   int i;
   num_to_str w;
   unsigned long j;

   LTC_ARGCHK(oid != NULL);
   LTC_ARGCHK(oidlen < INT_MAX);
   LTC_ARGCHK(outlen != NULL);

   if (OID == NULL || *outlen == 0) {
      w.max_len = ULONG_MAX;
      w.wr = NULL;
   } else {
      w.max_len = *outlen;
      w.wr = OID;
   }
   w.res_len = 0;
   w.err = CRYPT_OK;

   s_wr('\0', &w);
   for (i = oidlen; i --> 0;) {
      j = oid[i];
      if (j == 0) {
         s_wr('0', &w);
      } else {
         while (j > 0) {
            s_wr('0' + (j % 10), &w);
            j /= 10;
         }
      }
      if (i > 0) {
         s_wr('.', &w);
      }
   }
   if (w.err != CRYPT_OK) {
      return w.err;
   }
   if (*outlen < w.res_len || OID == NULL) {
      *outlen = w.res_len;
      return CRYPT_BUFFER_OVERFLOW;
   }
   LTC_ARGCHK(OID != NULL);
   XMEMMOVE(OID, OID + (w.max_len - w.res_len), w.res_len);
   *outlen = w.res_len;
   return CRYPT_OK;
}
