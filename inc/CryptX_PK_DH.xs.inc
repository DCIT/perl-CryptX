MODULE = CryptX         PACKAGE = Crypt::PK::DH

PROTOTYPES: DISABLE

Crypt::PK::DH
_new(Class)
    CODE:
    {
        int rv;
        Newz(0, RETVAL, 1, struct dh_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        RETVAL->key.type = -1;
        RETVAL->pindex = find_prng("chacha20");
        if (RETVAL->pindex == -1) {
          Safefree(RETVAL);
          croak("FATAL: find_prng('chacha20') failed");
        }
        rv = rng_make_prng(320, RETVAL->pindex, &RETVAL->pstate, NULL); /* 320bits = 40bytes */
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: rng_make_prng failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
_generate_key_size(Crypt::PK::DH self, int groupsize=256)
    PPCODE:
    {
        int rv;
        rv = dh_set_pg_groupsize(groupsize, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dh_set_pg_groupsize failed: %s", error_to_string(rv));
        rv = dh_generate_key(&self->pstate, self->pindex, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dh_generate_key failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_generate_key_gp(Crypt::PK::DH self, char *g, char *p)
    PPCODE:
    {
        int rv;
        unsigned char pbin[1024], gbin[512];
        unsigned long plen=sizeof(pbin), glen=sizeof(gbin);

        if (p && strlen(p) > 0 && g && strlen(g) > 0) {
          rv = radix_to_bin(p, 16, pbin, &plen);
          if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(p) failed: %s", error_to_string(rv));
          rv = radix_to_bin(g, 16, gbin, &glen);
          if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(g) failed: %s", error_to_string(rv));

          rv = dh_set_pg(pbin, plen, gbin, glen, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: dh_set_pg failed: %s", error_to_string(rv));
          rv = dh_generate_key(&self->pstate, self->pindex, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: dh_generate_key failed: %s", error_to_string(rv));
        }

        XPUSHs(ST(0)); /* return self */
    }

void
_generate_key_dhparam(Crypt::PK::DH self, SV * dhparam)
    PPCODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;
        data = (unsigned char *)SvPVbyte(dhparam, data_len);
        /* load d p q */
        rv = dh_set_pg_dhparam(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dh_set_pg_dhparam failed: %s", error_to_string(rv));
        /* gen the key */
        rv = dh_generate_key(&self->pstate, self->pindex, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dh_generate_key failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_import(Crypt::PK::DH self, SV * key_data)
    PPCODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->key.type != -1) { dh_free(&self->key); self->key.type = -1; }
        rv = dh_import(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dh_import failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_import_raw(Crypt::PK::DH self, SV * raw_key, int type, char * g, char * p)
    PPCODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;
        unsigned char pbin[1024], gbin[512];
        unsigned long plen=sizeof(pbin), glen=sizeof(gbin);

        data = (unsigned char *)SvPVbyte(raw_key, data_len);
        if (self->key.type != -1) { dh_free(&self->key); self->key.type = -1; }

        if (p && strlen(p) > 0 && g && strlen(g) > 0) {
          rv = radix_to_bin(p, 16, pbin, &plen);
          if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(p) failed: %s", error_to_string(rv));
          rv = radix_to_bin(g, 16, gbin, &glen);
          if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(g) failed: %s", error_to_string(rv));

          rv = dh_set_pg(pbin, plen, gbin, glen, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: dh_set_pg failed: %s", error_to_string(rv));

          if (type == 0) {
            /* public */
            rv = dh_set_key(data, (unsigned long)data_len, PK_PUBLIC, &self->key);
            if (rv != CRYPT_OK) croak("FATAL: dh_set_key failed: %s", error_to_string(rv));
          }
          else if (type == 1) {
            /* private */
            rv = dh_set_key(data, (unsigned long)data_len, PK_PRIVATE, &self->key);
            if (rv != CRYPT_OK) croak("FATAL: dh_set_key failed: %s", error_to_string(rv));
          }
          else {
            croak("FATAL: import_raw invalid type '%d'", type);
          }
        }

        XPUSHs(ST(0)); /* return self */
    }

int
is_private(Crypt::PK::DH self)
    CODE:
        if (self->key.type == -1) XSRETURN_UNDEF;
        RETVAL = (self->key.type == PK_PRIVATE) ? 1 : 0;
    OUTPUT:
        RETVAL

int
size(Crypt::PK::DH self)
    CODE:
        if (self->key.type == -1) XSRETURN_UNDEF;
        RETVAL = dh_get_groupsize(&self->key);
    OUTPUT:
        RETVAL

SV*
key2hash(Crypt::PK::DH self)
    PREINIT:
        HV *rv_hash;
        long siz;
        char buf[20001];
        SV **not_used;
    CODE:
        if (self->key.type == -1) XSRETURN_UNDEF;
        rv_hash = newHV();
        /* x */
        siz = (self->key.x) ? mp_unsigned_bin_size(self->key.x) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'x' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.x, buf, 20000, 0);
          not_used = hv_store(rv_hash, "x", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "x", 1, newSVpv("", 0), 0);
        }
        /* y */
        siz = (self->key.y) ? mp_unsigned_bin_size(self->key.y) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'y' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.y, buf, 20000, 0);
          not_used = hv_store(rv_hash, "y", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "y", 1, newSVpv("", 0), 0);
        }
        /* p */
        siz = (self->key.prime) ? mp_unsigned_bin_size(self->key.prime) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'p' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.prime, buf, 20000, 0);
          not_used = hv_store(rv_hash, "p", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else {
          not_used = hv_store(rv_hash, "p", 1, newSVpv("", 0), 0);
        }

        /* g */
        siz = (self->key.base) ? mp_unsigned_bin_size(self->key.base) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'g' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.base, buf, 20000, 0);
          not_used = hv_store(rv_hash, "g", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else {
          not_used = hv_store(rv_hash, "g", 1, newSVpv("", 0), 0);
        }
        /* size */
        not_used = hv_store(rv_hash, "size", 4, newSViv(dh_get_groupsize(&self->key)), 0);
        /* type */
        not_used = hv_store(rv_hash, "type", 4, newSViv(self->key.type), 0);
        LTC_UNUSED_PARAM(not_used);
        RETVAL = newRV_noinc((SV*)rv_hash);
    OUTPUT:
        RETVAL

SV*
params2hash(Crypt::PK::DH self)
    PREINIT:
        HV *rv_hash;
        long siz;
        char buf[20001];
        SV **not_used;
    CODE:
        if (self->key.type == -1) XSRETURN_UNDEF;
        rv_hash = newHV();
        /* p */
        siz = (self->key.prime) ? mp_unsigned_bin_size(self->key.prime) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'p' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.prime, buf, 20000, 0);
          not_used = hv_store(rv_hash, "p", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else {
          not_used = hv_store(rv_hash, "p", 1, newSVpv("", 0), 0);
        }

        /* g */
        siz = (self->key.base) ? mp_unsigned_bin_size(self->key.base) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'g' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.base, buf, 20000, 0);
          not_used = hv_store(rv_hash, "g", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else {
          not_used = hv_store(rv_hash, "g", 1, newSVpv("", 0), 0);
        }
        if (not_used) not_used = NULL; /* just silence the warning: variable 'not_used' set but not used */
        RETVAL = newRV_noinc((SV*)rv_hash);
    OUTPUT:
        RETVAL

SV *
export_key(Crypt::PK::DH self, char * type)
    CODE:
    {
        int rv;
        unsigned long int out_len = 4096;
        unsigned char out[4096];

        RETVAL = newSVpvn(NULL, 0); /* undef */
        if (strnEQ(type, "private", 7)) {
          rv = dh_export(out, &out_len, PK_PRIVATE, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: dh_export(PK_PRIVATE) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else if (strnEQ(type, "public", 6)) {
          rv = dh_export(out, &out_len, PK_PUBLIC, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: dh_export(PK_PUBLIC) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else {
          croak("FATAL: export_key_der invalid type '%s'", type);
        }
    }
    OUTPUT:
        RETVAL

SV *
shared_secret(Crypt::PK::DH self, Crypt::PK::DH pubkey)
    CODE:
    {
        int rv;
        unsigned long buffer_len = 1024;
        unsigned char buffer[1024];

        rv = dh_shared_secret(&self->key, &pubkey->key, buffer, &buffer_len);
        if (rv != CRYPT_OK) croak("FATAL: dh_shared_secret failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)buffer, buffer_len);
    }
    OUTPUT:
        RETVAL

SV *
export_key_raw(Crypt::PK::DH self, char * type)
    CODE:
    {
        int rv;
        unsigned char out[1024];
        unsigned long out_len = 1024;

        RETVAL = newSVpvn(NULL, 0); /* undef */
        if (strnEQ(type, "private", 7)) {
          rv = dh_export_key(out, &out_len, PK_PRIVATE, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: dh_export_key(PK_PRIVATE) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else if (strnEQ(type, "public", 6)) {
          rv = dh_export_key(out, &out_len, PK_PUBLIC, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: dh_export_key(PK_PUBLIC) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else {
          croak("FATAL: export_key_raw: invalid type '%s'", type);
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::PK::DH self)
    CODE:
        if (self->key.type != -1) { dh_free(&self->key); self->key.type = -1; }
        Safefree(self);
