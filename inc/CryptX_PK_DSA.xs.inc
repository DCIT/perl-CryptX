MODULE = CryptX         PACKAGE = Crypt::PK::DSA

PROTOTYPES: DISABLE

Crypt::PK::DSA
_new(Class)
    CODE:
    {
        int rv;
        Newz(0, RETVAL, 1, struct dsa_struct);
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
_generate_key_size(Crypt::PK::DSA self, int group_size=30, int modulus_size=256)
    PPCODE:
    {
        int rv;
        /* gen the key */
        rv = dsa_make_key(&self->pstate, self->pindex, group_size, modulus_size, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dsa_make_key failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_generate_key_dsaparam(Crypt::PK::DSA self, SV * dsaparam)
    PPCODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;
        data = (unsigned char *)SvPVbyte(dsaparam, data_len);
        /* load d p q */
        rv = dsa_set_pqg_dsaparam(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dsa_set_pqg_dsaparam failed: %s", error_to_string(rv));
        /* gen the key */
        rv = dsa_generate_key(&self->pstate, self->pindex, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dsa_generate_key failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_generate_key_pqg_hex(Crypt::PK::DSA self, char *p, char *q, char *g)
    PPCODE:
    {
        int rv;
        unsigned char pbin[512], qbin[512], gbin[512];
        unsigned long plen=sizeof(pbin), qlen=sizeof(qbin), glen=sizeof(gbin);
        if (!p || !strlen(p) || !q || !strlen(q) || !g || !strlen(g)) {
          croak("FATAL: generate_key_pqg_hex incomplete args");
        }
        /* set p q g */
        rv = radix_to_bin(p, 16, pbin, &plen);
        if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(p) failed: %s", error_to_string(rv));
        rv = radix_to_bin(q, 16, qbin, &qlen);
        if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(q) failed: %s", error_to_string(rv));
        rv = radix_to_bin(g, 16, gbin, &glen);
        if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(g) failed: %s", error_to_string(rv));
        rv = dsa_set_pqg(pbin, plen, qbin, qlen, gbin, glen, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dsa_set_pqg failed: %s", error_to_string(rv));
        /* gen the key */
        rv = dsa_generate_key(&self->pstate, self->pindex, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dsa_generate_key failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_import(Crypt::PK::DSA self, SV * key_data)
    PPCODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->key.type != -1) { dsa_free(&self->key); self->key.type = -1; }
        rv = dsa_import(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dsa_import failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_import_hex(Crypt::PK::DSA self, char *p, char *q, char *g, char *x, char *y)
    PPCODE:
    {
        int rv;
        unsigned char pbin[512], qbin[512], gbin[512], xbin[512], ybin[512];
        unsigned long plen=sizeof(pbin), qlen=sizeof(qbin), glen=sizeof(gbin), xlen=sizeof(xbin), ylen=sizeof(ybin);

        if (self->key.type != -1) { dsa_free(&self->key); self->key.type = -1; }

        if (p && strlen(p) > 0 && q && strlen(q) > 0 && g && strlen(g) > 0 && y && strlen(y) > 0) {
          rv = radix_to_bin(p, 16, pbin, &plen);
          if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(p) failed: %s", error_to_string(rv));
          rv = radix_to_bin(q, 16, qbin, &qlen);
          if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(q) failed: %s", error_to_string(rv));
          rv = radix_to_bin(g, 16, gbin, &glen);
          if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(g) failed: %s", error_to_string(rv));
          rv = dsa_set_pqg(pbin, plen, qbin, qlen, gbin, glen, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: dsa_set_pqg failed: %s", error_to_string(rv));

          rv = radix_to_bin(y, 16, ybin, &ylen);
          if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(y) failed: %s", error_to_string(rv));
          if (x && strlen(x) > 0) {
            /* private */
            rv = radix_to_bin(x, 16, xbin, &xlen);
            if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(x) failed: %s", error_to_string(rv));
            rv = dsa_set_key(xbin, xlen, PK_PRIVATE, &self->key);
            if (rv != CRYPT_OK) croak("FATAL: dsa_set_key failed: %s", error_to_string(rv));
          }
          else {
            /* public */
            rv = dsa_set_key(ybin, ylen, PK_PUBLIC, &self->key);
            if (rv != CRYPT_OK) croak("FATAL: dsa_set_key failed: %s", error_to_string(rv));
          }
        }

        XPUSHs(ST(0)); /* return self */
    }

int
is_private(Crypt::PK::DSA self)
    CODE:
        if (self->key.type == -1 || self->key.qord <= 0) XSRETURN_UNDEF;
        RETVAL = (self->key.type == PK_PRIVATE) ? 1 : 0;
    OUTPUT:
        RETVAL

int
size(Crypt::PK::DSA self)
    CODE:
        if (self->key.type == -1 || self->key.qord <= 0) XSRETURN_UNDEF;
        RETVAL = mp_unsigned_bin_size(self->key.p);
    OUTPUT:
        RETVAL

int
size_q(Crypt::PK::DSA self)
    CODE:
        if (self->key.type == -1 || self->key.qord <= 0) XSRETURN_UNDEF;
        RETVAL = mp_unsigned_bin_size(self->key.q);
    OUTPUT:
        RETVAL

SV*
key2hash(Crypt::PK::DSA self)
    PREINIT:
        HV *rv_hash;
        long siz, qsize, psize;
        char buf[20001];
        SV **not_used;
    CODE:
        if (self->key.type == -1 || self->key.qord <= 0) XSRETURN_UNDEF;
        qsize = mp_unsigned_bin_size(self->key.q);
        psize = mp_unsigned_bin_size(self->key.p);
        rv_hash = newHV();
        /* g */
        siz = (self->key.g) ? mp_unsigned_bin_size(self->key.g) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'g' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.g, buf, 20000, 0);
          not_used = hv_store(rv_hash, "g", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "g", 1, newSVpv("", 0), 0);
        }
        /* q */
        siz = (self->key.q) ? mp_unsigned_bin_size(self->key.q) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'q' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.q, buf, 20000, 0);
          not_used = hv_store(rv_hash, "q", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "q", 1, newSVpv("", 0), 0);
        }
        /* p */
        siz = (self->key.p) ? mp_unsigned_bin_size(self->key.p) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'p' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.p, buf, 20000, 0);
          not_used = hv_store(rv_hash, "p", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "p", 1, newSVpv("", 0), 0);
        }
        /* x */
        siz = (self->key.x) ? mp_unsigned_bin_size(self->key.x) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'x' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.x, buf, 20000, qsize*2);
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
          mp_tohex_with_leading_zero(self->key.y, buf, 20000, psize*2);
          not_used = hv_store(rv_hash, "y", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "y", 1, newSVpv("", 0), 0);
        }
        /* size */
        not_used = hv_store(rv_hash, "size", 4, newSViv(qsize), 0);
        /* type */
        not_used = hv_store(rv_hash, "type", 4, newSViv(self->key.type), 0);
        LTC_UNUSED_PARAM(not_used);
        RETVAL = newRV_noinc((SV*)rv_hash);
    OUTPUT:
        RETVAL

SV *
export_key_der(Crypt::PK::DSA self, char * type)
    CODE:
    {
        int rv;
        unsigned char out[4096];
        unsigned long int out_len = 4096;

        RETVAL = newSVpvn(NULL, 0); /* undef */
        if (strnEQ(type, "private", 7)) {
          rv = dsa_export(out, &out_len, PK_PRIVATE|PK_STD, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: dsa_export(PK_PRIVATE|PK_STD) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else if (strnEQ(type, "public", 6)) {
          rv = dsa_export(out, &out_len, PK_PUBLIC|PK_STD, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: dsa_export(PK_PUBLIC|PK_STD) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else {
          croak("FATAL: export_key_der invalid type '%s'", type);
        }
    }
    OUTPUT:
        RETVAL

SV *
encrypt(Crypt::PK::DSA self, SV * data, const char * hash_name = "SHA1")
    CODE:
    {
        int rv, hash_id;
        unsigned char *data_ptr=NULL;
        STRLEN data_len=0;
        unsigned char buffer[1024];
        unsigned long buffer_len = 1024;

        data_ptr = (unsigned char *)SvPVbyte(data, data_len);

        hash_id = _find_hash(hash_name);
        if (hash_id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);
        rv = dsa_encrypt_key(data_ptr, (unsigned long)data_len, buffer, &buffer_len,
                             &self->pstate, self->pindex,
                             hash_id, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dsa_encrypt_key failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)buffer, buffer_len);
    }
    OUTPUT:
        RETVAL

SV *
decrypt(Crypt::PK::DSA self, SV * data)
    CODE:
    {
        int rv;
        unsigned char *data_ptr=NULL;
        STRLEN data_len=0;
        unsigned char buffer[1024];
        unsigned long buffer_len = 1024;

        data_ptr = (unsigned char *)SvPVbyte(data, data_len);

        rv = dsa_decrypt_key(data_ptr, (unsigned long)data_len, buffer, &buffer_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dsa_decrypt_key_ex failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)buffer, buffer_len);
    }
    OUTPUT:
        RETVAL

SV *
sign_hash(Crypt::PK::DSA self, SV * data, const char * hash_name = "SHA1")
    ALIAS:
        sign_message = 1
    CODE:
    {
        int rv, id;
        unsigned char buffer[1024], tmp[MAXBLOCKSIZE], *data_ptr = NULL;
        unsigned long tmp_len = MAXBLOCKSIZE, buffer_len = 1024;
        STRLEN data_len = 0;

        data_ptr = (unsigned char *)SvPVbyte(data, data_len);
        if (ix == 1) {
          id = _find_hash(hash_name);
          if (id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);
          rv = hash_memory(id, data_ptr, (unsigned long)data_len, tmp, &tmp_len);
          if (rv != CRYPT_OK) croak("FATAL: hash_memory failed: %s", error_to_string(rv));
          data_ptr = tmp;
          data_len = tmp_len;
        }
        rv = dsa_sign_hash(data_ptr, (unsigned long)data_len, buffer, &buffer_len,
                           &self->pstate, self->pindex,
                           &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dsa_sign_hash_ex failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)buffer, buffer_len);
    }
    OUTPUT:
        RETVAL

int
verify_hash(Crypt::PK::DSA self, SV * sig, SV * data, const char * hash_name = "SHA1")
    ALIAS:
        verify_message = 1
    CODE:
    {
        int rv, stat, id;
        unsigned char tmp[MAXBLOCKSIZE], *data_ptr = NULL, *sig_ptr = NULL;
        unsigned long tmp_len = MAXBLOCKSIZE;
        STRLEN data_len = 0, sig_len = 0;

        data_ptr = (unsigned char *)SvPVbyte(data, data_len);
        sig_ptr = (unsigned char *)SvPVbyte(sig, sig_len);
        if (ix == 1) {
          id = _find_hash(hash_name);
          if (id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);
          rv = hash_memory(id, data_ptr, (unsigned long)data_len, tmp, &tmp_len);
          if (rv != CRYPT_OK) croak("FATAL: hash_memory failed: %s", error_to_string(rv));
          data_ptr = tmp;
          data_len = tmp_len;
        }
        RETVAL = 1;
        stat = 0;
        rv = dsa_verify_hash(sig_ptr, (unsigned long)sig_len, data_ptr, (unsigned long)data_len, &stat, &self->key);
        if (rv != CRYPT_OK || stat != 1) RETVAL = 0;
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::PK::DSA self)
    CODE:
        if (self->key.type != -1) { dsa_free(&self->key); self->key.type = -1; }
        Safefree(self);

