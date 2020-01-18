MODULE = CryptX         PACKAGE = Crypt::PK::X25519

PROTOTYPES: DISABLE

Crypt::PK::X25519
_new(Class)
    CODE:
    {
        int rv;
        Newz(0, RETVAL, 1, struct curve25519_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        RETVAL->pindex = find_prng("chacha20");
        RETVAL->key.type = -1;
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
        /* gen the key */
        rv = x25519_make_key(&self->pstate, self->pindex, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: x25519_make_key failed: %s", error_to_string(rv));
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
        self->key.type = -1;
        rv = x25519_import(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: x25519_import failed: %s", error_to_string(rv));
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
        self->key.type = -1;
        rv = x25519_import_pkcs8(data, (unsigned long)data_len, pwd, (unsigned long)pwd_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: x25519_import_pkcs8 failed: %s", error_to_string(rv));
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
        self->key.type = -1;
        rv = x25519_import_x509(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: x25519_import_x509 failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_import_key_data(Crypt::PK::X25519 self, SV * priv, SV * pub)
    PPCODE:
    {
        int rv, type;
        unsigned char *priv_data=NULL, *pub_data=NULL;
        STRLEN priv_len=0, pub_len=0;

        if (SvOK(priv)) {
          priv_data = (unsigned char *)SvPVbyte(priv, priv_len);
        }
        if (SvOK(pub)) {
          pub_data = (unsigned char *)SvPVbyte(pub, pub_len);
        }
        self->key.type = -1;
        rv = x25519_set_key(priv_data, (unsigned long)priv_len, pub_data, (unsigned long)pub_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: x25519_set_key failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

int
is_private(Crypt::PK::X25519 self)
    CODE:
        if (self->key.type == -1) XSRETURN_UNDEF;
        RETVAL = (self->key.type == PK_PRIVATE) ? 1 : 0;
    OUTPUT:
        RETVAL

SV*
key2hash(Crypt::PK::X25519 self)
    PREINIT:
        HV *rv_hash;
        char buf[20001];
        SV **not_used;
    CODE:
        if (self->key.type == -1) XSRETURN_UNDEF;
        rv_hash = newHV();
        /* priv */
        if (self->key.type == PK_PRIVATE) {
          not_used = hv_store(rv_hash, "priv", 4, newSVpv(self->key.priv, sizeof(self->key.priv)), 0);
        }
        else {
          not_used = hv_store(rv_hash, "priv", 4, &PL_sv_undef, 0);
        }
        /* pub */
        not_used = hv_store(rv_hash, "pub", 3, newSVpv(self->key.pub, sizeof(self->key.pub)), 0);
        /* algo */
        not_used = hv_store(rv_hash, "algo", 4, newSVpv("x25519", 0), 0);
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
          rv = x25519_export(out, &out_len, PK_PRIVATE, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: x25519_export(PK_PRIVATE) failed: %s", error_to_string(rv));
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

