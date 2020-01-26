MODULE = CryptX         PACKAGE = Crypt::PK::X25519

PROTOTYPES: DISABLE

Crypt::PK::X25519
_new(Class)
    CODE:
    {
        int rv;
        Newz(0, RETVAL, 1, struct x25519_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        RETVAL->initialized = 0;
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
generate_key(Crypt::PK::X25519 self)
    PPCODE:
    {
        int rv;
        self->initialized = 0;
        rv = x25519_make_key(&self->pstate, self->pindex, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: x25519_make_key failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import(Crypt::PK::X25519 self, SV * key_data)
    PPCODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        self->initialized = 0;
        rv = x25519_import(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: x25519_import failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import_pkcs8(Crypt::PK::X25519 self, SV * key_data, SV * passwd)
    PPCODE:
    {
        int rv;
        unsigned char *data=NULL, *pwd=NULL;
        STRLEN data_len=0, pwd_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (SvOK(passwd)) {
          pwd = (unsigned char *)SvPVbyte(passwd, pwd_len);
        }
        self->initialized = 0;
        rv = x25519_import_pkcs8(data, (unsigned long)data_len, pwd, (unsigned long)pwd_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: x25519_import_pkcs8 failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import_x509(Crypt::PK::X25519 self, SV * key_data)
    PPCODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        self->initialized = 0;
        rv = x25519_import_x509(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: x25519_import_x509 failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import_raw(Crypt::PK::X25519 self, SV * key, int which)
    PPCODE:
    {
        int rv;
        unsigned char *key_data=NULL;
        STRLEN key_len=0;

        if (SvOK(key)) {
          key_data = (unsigned char *)SvPVbyte(key, key_len);
        }
        self->initialized = 0;
        if (which == 0) {
          rv = x25519_import_raw(key_data, (unsigned long)key_len, PK_PUBLIC, &self->key);
        }
        else if (which == 1) {
          rv = x25519_import_raw(key_data, (unsigned long)key_len, PK_PRIVATE, &self->key);
        }
        else {
          croak("FATAL: import_raw invalid type '%d'", which);
        }
        if (rv != CRYPT_OK) croak("FATAL: x25519_import_raw failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

int
is_private(Crypt::PK::X25519 self)
    CODE:
        if (self->initialized == 0) XSRETURN_UNDEF;
        RETVAL = (self->key.type == PK_PRIVATE) ? 1 : 0;
    OUTPUT:
        RETVAL

SV*
key2hash(Crypt::PK::X25519 self)
    PREINIT:
        HV *rv_hash;
        char buf[32 * 2 + 1];
        unsigned long blen;
        SV **not_used;
        int rv;
    CODE:
        if (self->initialized == 0) XSRETURN_UNDEF;
        rv_hash = newHV();
        /* priv */
        if (self->key.type == PK_PRIVATE) {
          blen = sizeof(buf);
          rv = base16_encode(self->key.priv, sizeof(self->key.priv), buf, &blen, 0);
          if (rv != CRYPT_OK) croak("FATAL: base16_encode failed: %s", error_to_string(rv));
          not_used = hv_store(rv_hash, "priv", 4, newSVpv(buf, blen), 0);
        }
        else {
          not_used = hv_store(rv_hash, "priv", 4, newSVpvn(NULL, 0), 0); /* undef */
        }
        /* pub */
        blen = sizeof(buf);
        rv = base16_encode(self->key.pub, sizeof(self->key.pub), buf, &blen, 0);
        if (rv != CRYPT_OK) croak("FATAL: base16_encode failed: %s", error_to_string(rv));
        not_used = hv_store(rv_hash, "pub", 3, newSVpv(buf, blen), 0);
        /* curve */
        not_used = hv_store(rv_hash, "curve", 5, newSVpv("x25519", 0), 0);
        LTC_UNUSED_PARAM(not_used);
        RETVAL = newRV_noinc((SV*)rv_hash);
    OUTPUT:
        RETVAL

SV*
export_key_der(Crypt::PK::X25519 self, char * type)
    CODE:
    {
        int rv;
        unsigned char out[4096];
        unsigned long int out_len = sizeof(out);

        RETVAL = newSVpvn(NULL, 0); /* undef */
        if (strnEQ(type, "private", 7)) {
          rv = x25519_export(out, &out_len, PK_PRIVATE|PK_STD, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: x25519_export(PK_PRIVATE|PK_STD) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else if (strnEQ(type, "public", 6)) {
          rv = x25519_export(out, &out_len, PK_PUBLIC|PK_STD, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: x25519_export(PK_PUBLIC|PK_STD) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else {
          croak("FATAL: export_key_der invalid type '%s'", type);
        }
    }
    OUTPUT:
        RETVAL

SV*
export_key_raw(Crypt::PK::X25519 self, char * type)
    CODE:
    {
        int rv;
        unsigned char out[32];
        unsigned long int out_len = sizeof(out);

        RETVAL = newSVpvn(NULL, 0); /* undef */
        if (strnEQ(type, "private", 7)) {
          rv = x25519_export(out, &out_len, PK_PRIVATE, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: x25519_export(PK_PRIVATE) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else if (strnEQ(type, "public", 6)) {
          rv = x25519_export(out, &out_len, PK_PUBLIC, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: x25519_export(PK_PUBLIC) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else {
          croak("FATAL: export_key_raw invalid type '%s'", type);
        }
    }
    OUTPUT:
        RETVAL

SV *
shared_secret(Crypt::PK::X25519 self, Crypt::PK::X25519 pubkey)
    CODE:
    {
        int rv;
        unsigned char buffer[1024];
        unsigned long int buffer_len = sizeof(buffer);

        rv = x25519_shared_secret(&self->key, &pubkey->key, buffer, &buffer_len);
        if (rv != CRYPT_OK) croak("FATAL: x25519_shared_secret failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)buffer, buffer_len);
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::PK::X25519 self)
    CODE:
        Safefree(self);
