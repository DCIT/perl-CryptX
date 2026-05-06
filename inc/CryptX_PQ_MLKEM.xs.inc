MODULE = CryptX         PACKAGE = Crypt::PQ::MLKEM

PROTOTYPES: DISABLE

Crypt::PQ::MLKEM
_new(Class)
    CODE:
    {
        int rv;
        Newz(0, RETVAL, 1, struct cryptx_pq_mlkem_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        RETVAL->initialized = 0;
        RETVAL->pindex = find_prng("chacha20");
        RETVAL->last_pid = (IV)PerlProc_getpid();
        if (RETVAL->pindex == -1) {
          zeromem(RETVAL, sizeof(*RETVAL));
          Safefree(RETVAL);
          croak("FATAL: find_prng('chacha20') failed");
        }
        rv = rng_make_prng(320, RETVAL->pindex, &RETVAL->pstate, NULL); /* 320bits = 40bytes */
        if (rv != CRYPT_OK) {
          zeromem(RETVAL, sizeof(*RETVAL));
          Safefree(RETVAL);
          croak("FATAL: rng_make_prng failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
generate_key(Crypt::PQ::MLKEM self, char * alg_name)
    PPCODE:
    {
        int rv, alg;
        if (alg_name == NULL) croak("FATAL: undefined algorithm");
        if (mlkem_find_alg(alg_name, &alg) != CRYPT_OK)
            croak("FATAL: invalid ML-KEM algorithm '%s'", alg_name);
        if (self->initialized) {
            mlkem_free(&self->key);
            self->initialized = 0;
        }
        cryptx_internal_pk_prng_reseed(&self->pstate, self->pindex, &self->last_pid);
        rv = mlkem_make_key(&self->pstate, self->pindex, alg, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: mlkem_make_key failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
make_key_from_seed(Crypt::PQ::MLKEM self, SV * seed, char * alg_name)
    PPCODE:
    {
        int rv, alg;
        unsigned char *seed_data = NULL;
        STRLEN seed_len = 0;
        if (alg_name == NULL) croak("FATAL: undefined algorithm");
        if (mlkem_find_alg(alg_name, &alg) != CRYPT_OK)
            croak("FATAL: invalid ML-KEM algorithm '%s'", alg_name);
        if (!SvOK(seed)) croak("FATAL: undefined seed");
        seed_data = (unsigned char *)SvPVbyte(seed, seed_len);
        if (seed_len != LTC_MLKEM_KEYGEN_SEED_BYTES)
            croak("FATAL: ML-KEM seed must be exactly %d bytes", LTC_MLKEM_KEYGEN_SEED_BYTES);
        if (self->initialized) {
            mlkem_free(&self->key);
            self->initialized = 0;
        }
        rv = mlkem_make_key_from_seed(alg, seed_data, (unsigned long)seed_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: mlkem_make_key_from_seed failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import(Crypt::PQ::MLKEM self, SV * key_data)
    PPCODE:
    {
        int rv;
        unsigned char *data = NULL;
        STRLEN data_len = 0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->initialized) {
            mlkem_free(&self->key);
            self->initialized = 0;
        }
        rv = mlkem_import(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: mlkem_import failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import_pkcs8(Crypt::PQ::MLKEM self, SV * key_data, SV * passwd)
    PPCODE:
    {
        int rv;
        unsigned char *data = NULL;
        STRLEN data_len = 0;
        password_ctx pw_ctx = { cryptx_internal_password_cb_getpw, cryptx_internal_password_cb_free, passwd };

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->initialized) {
            mlkem_free(&self->key);
            self->initialized = 0;
        }
        if (SvOK(passwd)) {
          rv = mlkem_import_pkcs8(data, (unsigned long)data_len, &pw_ctx, &self->key);
        }
        else {
          rv = mlkem_import_pkcs8(data, (unsigned long)data_len, NULL, &self->key);
        }
        if (rv != CRYPT_OK) croak("FATAL: mlkem_import_pkcs8 failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import_pem(Crypt::PQ::MLKEM self, SV * key_data, SV * passwd)
    PPCODE:
    {
        int rv;
        unsigned char *data = NULL;
        STRLEN data_len = 0;
        password_ctx pw_ctx = { cryptx_internal_password_cb_getpw, cryptx_internal_password_cb_free, passwd };
        ltc_pka_key key_from_pem;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->initialized) {
            mlkem_free(&self->key);
            self->initialized = 0;
        }
        if (SvOK(passwd)) {
          rv = pem_decode_pkcs(data, (unsigned long)data_len, &key_from_pem, &pw_ctx);
        }
        else {
          rv = pem_decode_pkcs(data, (unsigned long)data_len, &key_from_pem, NULL);
        }
        if (rv != CRYPT_OK) croak("FATAL: pem_decode_pkcs failed: %s", error_to_string(rv));
        if (key_from_pem.id != LTC_PKA_MLKEM) {
          pka_key_free(&key_from_pem);
          croak("FATAL: pem_decode_pkcs decoded non-ML-KEM key");
        }
        self->key = key_from_pem.u.mlkem;
        XMEMSET(&key_from_pem.u.mlkem, 0, sizeof(key_from_pem.u.mlkem));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import_x509(Crypt::PQ::MLKEM self, SV * key_data)
    PPCODE:
    {
        int rv;
        unsigned char *data = NULL;
        STRLEN data_len = 0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->initialized) {
            mlkem_free(&self->key);
            self->initialized = 0;
        }
        rv = mlkem_import_x509(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: mlkem_import_x509 failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
import_key_raw(Crypt::PQ::MLKEM self, SV * key, char * type, char * alg_name)
    PPCODE:
    {
        int rv, alg;
        unsigned char *key_data = NULL;
        STRLEN key_len = 0;

        if (!SvOK(key))      croak("FATAL: undefined key");
        if (type == NULL)    croak("FATAL: undefined type");
        if (alg_name == NULL) croak("FATAL: undefined algorithm");
        if (mlkem_find_alg(alg_name, &alg) != CRYPT_OK)
            croak("FATAL: invalid ML-KEM algorithm '%s'", alg_name);
        key_data = (unsigned char *)SvPVbyte(key, key_len);
        if (self->initialized) {
            mlkem_free(&self->key);
            self->initialized = 0;
        }
        if (strEQ(type, "public")) {
          rv = mlkem_import_raw(key_data, (unsigned long)key_len, PK_PUBLIC, alg, &self->key);
        }
        else if (strEQ(type, "private")) {
          rv = mlkem_import_raw(key_data, (unsigned long)key_len, PK_PRIVATE, alg, &self->key);
        }
        else {
          croak("FATAL: invalid key type '%s'", type);
        }
        if (rv != CRYPT_OK) croak("FATAL: mlkem_import_raw failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

int
is_private(Crypt::PQ::MLKEM self)
    CODE:
        if (self->initialized == 0) XSRETURN_UNDEF;
        RETVAL = (self->key.type == PK_PRIVATE) ? 1 : 0;
    OUTPUT:
        RETVAL

SV *
algorithm(Crypt::PQ::MLKEM self)
    CODE:
    {
        const char *name;
        if (self->initialized == 0) XSRETURN_UNDEF;
        if (mlkem_alg_name(self->key.alg, &name) != CRYPT_OK)
            croak("FATAL: unknown ML-KEM algorithm");
        RETVAL = newSVpv(name, 0);
    }
    OUTPUT:
        RETVAL

SV*
key2hash(Crypt::PQ::MLKEM self)
    PREINIT:
        HV *rv_hash;
        SV **not_used;
        const char *name;
        char *buf = NULL;
        unsigned long blen, needed;
        int rv;
    CODE:
        if (self->initialized == 0) XSRETURN_UNDEF;
        rv_hash = newHV();
        if (mlkem_alg_name(self->key.alg, &name) != CRYPT_OK)
            croak("FATAL: unknown ML-KEM algorithm");
        not_used = hv_store(rv_hash, "alg", 3, newSVpv(name, 0), 0);
        /* priv */
        if (self->key.type == PK_PRIVATE && self->key.sk != NULL) {
          needed = self->key.sklen * 2 + 1;
          Newz(0, buf, needed, char);
          if (buf == NULL) croak("FATAL: Newz failed");
          blen = needed;
          rv = base16_encode(self->key.sk, self->key.sklen, buf, &blen, 0);
          if (rv != CRYPT_OK) { Safefree(buf); croak("FATAL: base16_encode failed: %s", error_to_string(rv)); }
          not_used = hv_store(rv_hash, "priv", 4, newSVpv(buf, blen), 0);
          Safefree(buf); buf = NULL;
        }
        else {
          not_used = hv_store(rv_hash, "priv", 4, newSVpvn(NULL, 0), 0); /* undef */
        }
        /* pub */
        if (self->key.pk != NULL) {
          needed = self->key.pklen * 2 + 1;
          Newz(0, buf, needed, char);
          if (buf == NULL) croak("FATAL: Newz failed");
          blen = needed;
          rv = base16_encode(self->key.pk, self->key.pklen, buf, &blen, 0);
          if (rv != CRYPT_OK) { Safefree(buf); croak("FATAL: base16_encode failed: %s", error_to_string(rv)); }
          not_used = hv_store(rv_hash, "pub", 3, newSVpv(buf, blen), 0);
          Safefree(buf); buf = NULL;
        }
        else {
          not_used = hv_store(rv_hash, "pub", 3, newSVpvn(NULL, 0), 0);
        }
        LTC_UNUSED_PARAM(not_used);
        RETVAL = newRV_noinc((SV*)rv_hash);
    OUTPUT:
        RETVAL

SV*
export_key_der(Crypt::PQ::MLKEM self, char * type)
    CODE:
    {
        int rv;
        unsigned long out_len;
        unsigned char *out = NULL;

        if (self->initialized == 0) XSRETURN_UNDEF;
        if (strEQ(type, "private")) {
          out_len = self->key.sklen + 64;
          Newz(0, out, out_len, unsigned char);
          if (out == NULL) croak("FATAL: Newz failed");
          rv = mlkem_export(out, &out_len, PK_PRIVATE|PK_STD, &self->key);
          if (rv != CRYPT_OK) { Safefree(out); croak("FATAL: mlkem_export(PK_PRIVATE|PK_STD) failed: %s", error_to_string(rv)); }
          RETVAL = newSVpvn((char*)out, out_len);
          zeromem(out, self->key.sklen + 64);
          Safefree(out);
        }
        else if (strEQ(type, "public")) {
          out_len = self->key.pklen + 64;
          Newz(0, out, out_len, unsigned char);
          if (out == NULL) croak("FATAL: Newz failed");
          rv = mlkem_export(out, &out_len, PK_PUBLIC|PK_STD, &self->key);
          if (rv != CRYPT_OK) { Safefree(out); croak("FATAL: mlkem_export(PK_PUBLIC|PK_STD) failed: %s", error_to_string(rv)); }
          RETVAL = newSVpvn((char*)out, out_len);
          Safefree(out);
        }
        else {
          croak("FATAL: export_key_der invalid type '%s'", type);
        }
    }
    OUTPUT:
        RETVAL

SV*
export_key_raw(Crypt::PQ::MLKEM self, char * type)
    CODE:
    {
        int rv;
        unsigned long out_len;
        unsigned char *out = NULL;

        if (self->initialized == 0) XSRETURN_UNDEF;
        if (strEQ(type, "private")) {
          out_len = self->key.sklen;
          if (out_len == 0) croak("FATAL: not a private key");
          Newz(0, out, out_len, unsigned char);
          if (out == NULL) croak("FATAL: Newz failed");
          rv = mlkem_export_raw(out, &out_len, PK_PRIVATE, &self->key);
          if (rv != CRYPT_OK) { Safefree(out); croak("FATAL: mlkem_export_raw(PK_PRIVATE) failed: %s", error_to_string(rv)); }
          RETVAL = newSVpvn((char*)out, out_len);
          zeromem(out, self->key.sklen);
          Safefree(out);
        }
        else if (strEQ(type, "public")) {
          out_len = self->key.pklen;
          Newz(0, out, out_len, unsigned char);
          if (out == NULL) croak("FATAL: Newz failed");
          rv = mlkem_export_raw(out, &out_len, PK_PUBLIC, &self->key);
          if (rv != CRYPT_OK) { Safefree(out); croak("FATAL: mlkem_export_raw(PK_PUBLIC) failed: %s", error_to_string(rv)); }
          RETVAL = newSVpvn((char*)out, out_len);
          Safefree(out);
        }
        else {
          croak("FATAL: export_key_raw invalid type '%s'", type);
        }
    }
    OUTPUT:
        RETVAL

void
encapsulate(Crypt::PQ::MLKEM self)
    PPCODE:
    {
        int rv;
        unsigned long ct_len, ss_len;
        unsigned char *ct = NULL;
        unsigned char ss[LTC_MLKEM_SHARED_SECRET_BYTES];

        if (self->initialized == 0) croak("FATAL: no key loaded");
        if (self->key.pk == NULL) croak("FATAL: no public key");
        rv = mlkem_get_sizes(self->key.alg, NULL, NULL, &ct_len, &ss_len);
        if (rv != CRYPT_OK) croak("FATAL: mlkem_get_sizes failed: %s", error_to_string(rv));
        Newz(0, ct, ct_len, unsigned char);
        if (ct == NULL) croak("FATAL: Newz failed");
        cryptx_internal_pk_prng_reseed(&self->pstate, self->pindex, &self->last_pid);
        rv = mlkem_encaps(ct, &ct_len, ss, &ss_len, &self->pstate, self->pindex, &self->key);
        if (rv != CRYPT_OK) { Safefree(ct); croak("FATAL: mlkem_encaps failed: %s", error_to_string(rv)); }
        EXTEND(SP, 2);
        PUSHs(sv_2mortal(newSVpvn((char*)ct, ct_len)));
        PUSHs(sv_2mortal(newSVpvn((char*)ss, ss_len)));
        Safefree(ct);
        zeromem(ss, sizeof(ss));
    }

void
encapsulate_ex(Crypt::PQ::MLKEM self, SV * m)
    PPCODE:
    {
        int rv;
        unsigned long ct_len, ss_len;
        unsigned char *ct = NULL, *m_data = NULL;
        STRLEN m_len = 0;
        unsigned char ss[LTC_MLKEM_SHARED_SECRET_BYTES];

        if (self->initialized == 0) croak("FATAL: no key loaded");
        if (self->key.pk == NULL) croak("FATAL: no public key");
        if (!SvOK(m)) croak("FATAL: undefined m");
        m_data = (unsigned char *)SvPVbyte(m, m_len);
        if (m_len != LTC_MLKEM_M_BYTES)
            croak("FATAL: ML-KEM m must be exactly %d bytes", LTC_MLKEM_M_BYTES);
        rv = mlkem_get_sizes(self->key.alg, NULL, NULL, &ct_len, &ss_len);
        if (rv != CRYPT_OK) croak("FATAL: mlkem_get_sizes failed: %s", error_to_string(rv));
        Newz(0, ct, ct_len, unsigned char);
        if (ct == NULL) croak("FATAL: Newz failed");
        rv = mlkem_encaps_ex(ct, &ct_len, ss, &ss_len, m_data, (unsigned long)m_len, &self->key);
        if (rv != CRYPT_OK) { Safefree(ct); croak("FATAL: mlkem_encaps_ex failed: %s", error_to_string(rv)); }
        EXTEND(SP, 2);
        PUSHs(sv_2mortal(newSVpvn((char*)ct, ct_len)));
        PUSHs(sv_2mortal(newSVpvn((char*)ss, ss_len)));
        Safefree(ct);
        zeromem(ss, sizeof(ss));
    }

SV *
decapsulate(Crypt::PQ::MLKEM self, SV * ct)
    CODE:
    {
        int rv;
        unsigned char *ct_data = NULL;
        STRLEN ct_len = 0;
        unsigned char ss[LTC_MLKEM_SHARED_SECRET_BYTES];
        unsigned long ss_len = sizeof(ss);

        if (self->initialized == 0) croak("FATAL: no key loaded");
        if (self->key.type != PK_PRIVATE) croak("FATAL: not a private key");
        ct_data = (unsigned char *)SvPVbyte(ct, ct_len);
        rv = mlkem_decaps(ss, &ss_len, ct_data, (unsigned long)ct_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: mlkem_decaps failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)ss, ss_len);
        zeromem(ss, sizeof(ss));
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::PQ::MLKEM self)
    CODE:
        if (self->initialized) mlkem_free(&self->key);
        if (self->pindex >= 0 && prng_is_valid(self->pindex) == CRYPT_OK && prng_descriptor[self->pindex].done) {
          prng_descriptor[self->pindex].done(&self->pstate);
        }
        zeromem(self, sizeof(*self));
        Safefree(self);
