/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_MECC

static void _ecc_oid_lookup(ecc_key *key)
{
   int err;
   unsigned i;
   void *tmp;
   const ltc_ecc_set_type *set;

   key->dp.oidlen = 0;
   if ((err = mp_init(&tmp)) != CRYPT_OK) return;
   for (set = ltc_ecc_sets; set->name != NULL; set++) {
      if ((err = mp_read_radix(tmp, set->prime, 16)) != CRYPT_OK) continue;
      if ((mp_cmp(tmp, key->dp.prime) != LTC_MP_EQ))              continue;
      if ((err = mp_read_radix(tmp, set->order, 16)) != CRYPT_OK) continue;
      if ((mp_cmp(tmp, key->dp.order) != LTC_MP_EQ))              continue;
      if ((err = mp_read_radix(tmp, set->A,     16)) != CRYPT_OK) continue;
      if ((mp_cmp(tmp, key->dp.A) != LTC_MP_EQ))                  continue;
      if ((err = mp_read_radix(tmp, set->B,     16)) != CRYPT_OK) continue;
      if ((mp_cmp(tmp, key->dp.B) != LTC_MP_EQ))                  continue;
      if ((err = mp_read_radix(tmp, set->Gx,    16)) != CRYPT_OK) continue;
      if ((mp_cmp(tmp, key->dp.base.x) != LTC_MP_EQ))             continue;
      if ((err = mp_read_radix(tmp, set->Gy,    16)) != CRYPT_OK) continue;
      if ((mp_cmp(tmp, key->dp.base.y) != LTC_MP_EQ))             continue;
      if (key->dp.cofactor != set->cofactor)                      continue;
      break; /* found */
   }
   mp_clear(tmp);
   if (set->name != NULL) {
     /* OID found */
     key->dp.oidlen = set->oidlen;
     for(i = 0; i < set->oidlen; i++) key->dp.oid[i] = set->oid[i];
   }
}

int ecc_set_dp_oid(unsigned long *oid, unsigned long oidsize, ecc_key *key)
{
   int i;

   LTC_ARGCHK(oid != NULL);
   LTC_ARGCHK(oidsize > 0);

   for(i = 0; ltc_ecc_sets[i].name != NULL; i++) {
      if ((oidsize == ltc_ecc_sets[i].oidlen) &&
          (XMEM_NEQ(oid, ltc_ecc_sets[i].oid, sizeof(unsigned long) * ltc_ecc_sets[i].oidlen) == 0)) {
         break;
      }
   }
   if (ltc_ecc_sets[i].name == NULL) return CRYPT_ERROR; /* not found */
   return ecc_set_dp(&ltc_ecc_sets[i], key);
}

int ecc_set_dp_copy(ecc_key *srckey, ecc_key *key)
{
   unsigned long i;
   int err;

   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(srckey != NULL);

   if ((err = mp_init_multi(&key->dp.prime, &key->dp.order, &key->dp.A, &key->dp.B,
                            &key->dp.base.x, &key->dp.base.y, &key->dp.base.z,
                            &key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                            NULL)) != CRYPT_OK) {
      return err;
   }

   /* A, B, order, prime, Gx, Gy */
   if ((err = mp_copy(srckey->dp.prime,  key->dp.prime )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.order,  key->dp.order )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.A,      key->dp.A     )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.B,      key->dp.B     )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.base.x, key->dp.base.x)) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.base.y, key->dp.base.y)) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.base.z, key->dp.base.z)) != CRYPT_OK) { goto error; }
   /* cofactor & size */
   key->dp.cofactor = srckey->dp.cofactor;
   key->dp.size     = srckey->dp.size;
   /* OID */
   if (srckey->dp.oidlen > 0) {
     key->dp.oidlen = srckey->dp.oidlen;
     for (i = 0; i < key->dp.oidlen; i++) key->dp.oid[i] = srckey->dp.oid[i];
   }
   else {
     _ecc_oid_lookup(key); /* try to find OID in ltc_ecc_sets */
   }
   /* success */
   return CRYPT_OK;

error:
   ecc_free(key);
   return err;
}

int ecc_set_dp_bn(void *a, void *b, void *prime, void *order, void *gx, void *gy, unsigned long cofactor, ecc_key *key)
{
   int err;

   LTC_ARGCHK(key   != NULL);
   LTC_ARGCHK(a     != NULL);
   LTC_ARGCHK(b     != NULL);
   LTC_ARGCHK(prime != NULL);
   LTC_ARGCHK(order != NULL);
   LTC_ARGCHK(gx    != NULL);
   LTC_ARGCHK(gy    != NULL);

   if ((err = mp_init_multi(&key->dp.prime, &key->dp.order, &key->dp.A, &key->dp.B,
                            &key->dp.base.x, &key->dp.base.y, &key->dp.base.z,
                            &key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                            NULL)) != CRYPT_OK) {
      return err;
   }

   /* A, B, order, prime, Gx, Gy */
   if ((err = mp_copy(prime, key->dp.prime )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(order, key->dp.order )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(a,     key->dp.A     )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(b,     key->dp.B     )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(gx,    key->dp.base.x)) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(gy,    key->dp.base.y)) != CRYPT_OK) { goto error; }
   if ((err = mp_set(key->dp.base.z, 1)) != CRYPT_OK)      { goto error; }
   /* cofactor & size */
   key->dp.cofactor = cofactor;
   key->dp.size = mp_unsigned_bin_size(prime);
   /* try to find OID in ltc_ecc_sets */
   _ecc_oid_lookup(key);
   /* success */
   return CRYPT_OK;

error:
   ecc_free(key);
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
