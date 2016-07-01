MODULE = CryptX         PACKAGE = Crypt::PK::DSA

Crypt::PK::DSA
_new()
    CODE:
    {
        int rv;
        Newz(0, RETVAL, 1, struct dsa_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        RETVAL->key.type = -1;
        RETVAL->yarrow_prng_index = find_prng("yarrow");
        if(RETVAL->yarrow_prng_index==-1) croak("FATAL: find_prng('yarrow') failed");
        rv = rng_make_prng(256, RETVAL->yarrow_prng_index, &RETVAL->yarrow_prng_state, NULL);
        if (rv != CRYPT_OK) croak("FATAL: rng_make_prng failed: %s", error_to_string(rv));
    }
    OUTPUT:
        RETVAL

void
generate_key(Crypt::PK::DSA self, int group_size=30, int modulus_size=256)
    PPCODE:
    {
        int rv;
        /* add a small random entropy before generating key - not necessary as we have initialized prng with 256bit entropy in _new() */
        rv = rng_make_prng(64, self->yarrow_prng_index, &self->yarrow_prng_state, NULL);
        if (rv != CRYPT_OK) croak("FATAL: rng_make_prng failed: %s", error_to_string(rv));
        /* gen the key */
        rv = dsa_make_key(&self->yarrow_prng_state, self->yarrow_prng_index, group_size, modulus_size, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dsa_make_key failed: %s", error_to_string(rv));
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
        if (self->key.type != -1) { dsa_free(&self->key); self->key.type = -1; }
        rv = dsa_import_hex(p, q, g, x, y, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dsa_import_hex failed: %s", error_to_string(rv));
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
        RETVAL = mp_unsigned_bin_size(self->key.g);
    OUTPUT:
        RETVAL

int
size_q(Crypt::PK::DSA self)
    CODE:
        if (self->key.type == -1 || self->key.qord <= 0) XSRETURN_UNDEF;
        RETVAL = self->key.qord;
    OUTPUT:
        RETVAL

SV*
key2hash(Crypt::PK::DSA self)
    PREINIT:
        HV *rv_hash;
        long siz;
        char buf[20001];
        SV **not_used;
    CODE:
        if (self->key.type == -1 || self->key.qord <= 0) XSRETURN_UNDEF;
        rv_hash = newHV();
        /* =====> g */
        siz = (self->key.g) ? mp_unsigned_bin_size(self->key.g) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'g' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.g, buf, 20000);
          not_used = hv_store(rv_hash, "g", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "g", 1, newSVpv("", 0), 0);
        }
        /* =====> q */
        siz = (self->key.q) ? mp_unsigned_bin_size(self->key.q) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'q' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.q, buf, 20000);
          not_used = hv_store(rv_hash, "q", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "q", 1, newSVpv("", 0), 0);
        }
        /* =====> p */
        siz = (self->key.p) ? mp_unsigned_bin_size(self->key.p) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'p' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.p, buf, 20000);
          not_used = hv_store(rv_hash, "p", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "p", 1, newSVpv("", 0), 0);
        }
        /* =====> x */
        siz = (self->key.x) ? mp_unsigned_bin_size(self->key.x) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'x' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.x, buf, 20000);
          not_used = hv_store(rv_hash, "x", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "x", 1, newSVpv("", 0), 0);
        }
        /* =====> y */
        siz = (self->key.y) ? mp_unsigned_bin_size(self->key.y) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'y' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.y, buf, 20000);
          not_used = hv_store(rv_hash, "y", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "y", 1, newSVpv("", 0), 0);
        }
        /* =====> size */
        not_used = hv_store(rv_hash, "size", 4, newSViv(mp_unsigned_bin_size(self->key.q)), 0);
        /* =====> type */
        not_used = hv_store(rv_hash, "type", 4, newSViv(self->key.type), 0);
        if (not_used) not_used = NULL; /* just silence the warning: variable 'not_used' set but not used */
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
_encrypt(Crypt::PK::DSA self, SV * data, char * hash_name)
    CODE:
    {
        int rv, hash_id;
        unsigned char *data_ptr=NULL;
        STRLEN data_len=0;
        unsigned char buffer[1024];
        unsigned long buffer_len = 1024;

        data_ptr = (unsigned char *)SvPVbyte(data, data_len);

        hash_id = find_hash(hash_name);
        if(hash_id==-1) croak("FATAL: find_hash failed for '%s'", hash_name);
        rv = dsa_encrypt_key(data_ptr, (unsigned long)data_len, buffer, &buffer_len,
                             &self->yarrow_prng_state, self->yarrow_prng_index,
                             hash_id, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dsa_encrypt_key failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)buffer, buffer_len);
    }
    OUTPUT:
        RETVAL

SV *
_decrypt(Crypt::PK::DSA self, SV * data)
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
_sign(Crypt::PK::DSA self, SV * data)
    CODE:
    {
        int rv;
        unsigned char *data_ptr=NULL;
        STRLEN data_len=0;
        unsigned char buffer[1024];
        unsigned long buffer_len = 1024;

        data_ptr = (unsigned char *)SvPVbyte(data, data_len);

        rv = dsa_sign_hash(data_ptr, (unsigned long)data_len, buffer, &buffer_len,
                           &self->yarrow_prng_state, self->yarrow_prng_index,
                           &self->key);
        if (rv != CRYPT_OK) croak("FATAL: dsa_sign_hash_ex failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)buffer, buffer_len);
    }
    OUTPUT:
        RETVAL

int
_verify(Crypt::PK::DSA self, SV * sig, SV * data)
    CODE:
    {
        int rv, stat;
        unsigned char *data_ptr=NULL;
        STRLEN data_len=0;
        unsigned char *sig_ptr=NULL;
        STRLEN sig_len=0;

        data_ptr = (unsigned char *)SvPVbyte(data, data_len);
        sig_ptr = (unsigned char *)SvPVbyte(sig, sig_len);

        RETVAL = 1;
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

