MODULE = CryptX         PACKAGE = Crypt::PQ::SLHDSA

PROTOTYPES: DISABLE

Crypt::PQ::SLHDSA
_new(Class)
    CODE:
    {
        int rv;
        Newz(0, RETVAL, 1, struct cryptx_pq_slhdsa_struct);
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
generate_key(Crypt::PQ::SLHDSA self, char * alg_name)
    PPCODE:
    {
        int rv, alg;
        if (alg_name == NULL) croak("FATAL: undefined algorithm");
        if (slhdsa_find_alg(alg_name, &alg) != CRYPT_OK)
            croak("FATAL: invalid SLH-DSA algorithm '%s'", alg_name);
        if (self->initialized) {
            slhdsa_free(&self->key);
            self->initialized = 0;
        }
        cryptx_internal_pk_prng_reseed(&self->pstate, self->pindex, &self->last_pid);
        rv = slhdsa_make_key(&self->pstate, self->pindex, alg, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: slhdsa_make_key failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
make_key_from_seed(Crypt::PQ::SLHDSA self, SV * seed, char * alg_name)
    PPCODE:
    {
        int rv, alg;
        unsigned char *seed_data = NULL;
        STRLEN seed_len = 0;
        unsigned long expected_seed_len = 0;
        if (alg_name == NULL) croak("FATAL: undefined algorithm");
        if (slhdsa_find_alg(alg_name, &alg) != CRYPT_OK)
            croak("FATAL: invalid SLH-DSA algorithm '%s'", alg_name);
        if (!SvOK(seed)) croak("FATAL: undefined seed");
        seed_data = (unsigned char *)SvPVbyte(seed, seed_len);
        rv = slhdsa_get_sizes(alg, NULL, NULL, NULL, NULL, &expected_seed_len);
        if (rv != CRYPT_OK) croak("FATAL: slhdsa_get_sizes failed: %s", error_to_string(rv));
        if ((unsigned long)seed_len != expected_seed_len)
            croak("FATAL: SLH-DSA seed must be exactly %lu bytes for %s", expected_seed_len, alg_name);
        if (self->initialized) {
            slhdsa_free(&self->key);
            self->initialized = 0;
        }
        rv = slhdsa_make_key_from_seed(alg, seed_data, (unsigned long)seed_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: slhdsa_make_key_from_seed failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import(Crypt::PQ::SLHDSA self, SV * key_data)
    PPCODE:
    {
        int rv;
        unsigned char *data = NULL;
        STRLEN data_len = 0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->initialized) {
            slhdsa_free(&self->key);
            self->initialized = 0;
        }
        rv = slhdsa_import(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: slhdsa_import failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import_pkcs8(Crypt::PQ::SLHDSA self, SV * key_data, SV * passwd)
    PPCODE:
    {
        int rv;
        unsigned char *data = NULL;
        STRLEN data_len = 0;
        password_ctx pw_ctx = { cryptx_internal_password_cb_getpw, cryptx_internal_password_cb_free, passwd };

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->initialized) {
            slhdsa_free(&self->key);
            self->initialized = 0;
        }
        if (SvOK(passwd)) {
          rv = slhdsa_import_pkcs8(data, (unsigned long)data_len, &pw_ctx, &self->key);
        }
        else {
          rv = slhdsa_import_pkcs8(data, (unsigned long)data_len, NULL, &self->key);
        }
        if (rv != CRYPT_OK) croak("FATAL: slhdsa_import_pkcs8 failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import_pem(Crypt::PQ::SLHDSA self, SV * key_data, SV * passwd)
    PPCODE:
    {
        int rv;
        unsigned char *data = NULL;
        STRLEN data_len = 0;
        password_ctx pw_ctx = { cryptx_internal_password_cb_getpw, cryptx_internal_password_cb_free, passwd };
        ltc_pka_key key_from_pem;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->initialized) {
            slhdsa_free(&self->key);
            self->initialized = 0;
        }
        if (SvOK(passwd)) {
          rv = pem_decode_pkcs(data, (unsigned long)data_len, &key_from_pem, &pw_ctx);
        }
        else {
          rv = pem_decode_pkcs(data, (unsigned long)data_len, &key_from_pem, NULL);
        }
        if (rv != CRYPT_OK) croak("FATAL: pem_decode_pkcs failed: %s", error_to_string(rv));
        if (key_from_pem.id != LTC_PKA_SLHDSA) {
          pka_key_free(&key_from_pem);
          croak("FATAL: pem_decode_pkcs decoded non-SLH-DSA key");
        }
        self->key = key_from_pem.u.slhdsa;
        XMEMSET(&key_from_pem.u.slhdsa, 0, sizeof(key_from_pem.u.slhdsa));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import_x509(Crypt::PQ::SLHDSA self, SV * key_data)
    PPCODE:
    {
        int rv;
        unsigned char *data = NULL;
        STRLEN data_len = 0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->initialized) {
            slhdsa_free(&self->key);
            self->initialized = 0;
        }
        rv = slhdsa_import_x509(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: slhdsa_import_x509 failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
import_key_raw(Crypt::PQ::SLHDSA self, SV * key, char * type, char * alg_name)
    PPCODE:
    {
        int rv, alg;
        unsigned char *key_data = NULL;
        STRLEN key_len = 0;

        if (!SvOK(key))      croak("FATAL: undefined key");
        if (type == NULL)    croak("FATAL: undefined type");
        if (alg_name == NULL) croak("FATAL: undefined algorithm");
        if (slhdsa_find_alg(alg_name, &alg) != CRYPT_OK)
            croak("FATAL: invalid SLH-DSA algorithm '%s'", alg_name);
        key_data = (unsigned char *)SvPVbyte(key, key_len);
        if (self->initialized) {
            slhdsa_free(&self->key);
            self->initialized = 0;
        }
        if (strEQ(type, "public")) {
          rv = slhdsa_import_raw(key_data, (unsigned long)key_len, PK_PUBLIC, alg, &self->key);
        }
        else if (strEQ(type, "private")) {
          rv = slhdsa_import_raw(key_data, (unsigned long)key_len, PK_PRIVATE, alg, &self->key);
        }
        else {
          croak("FATAL: invalid key type '%s'", type);
        }
        if (rv != CRYPT_OK) croak("FATAL: slhdsa_import_raw failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

int
is_private(Crypt::PQ::SLHDSA self)
    CODE:
        if (self->initialized == 0) XSRETURN_UNDEF;
        RETVAL = (self->key.type == PK_PRIVATE) ? 1 : 0;
    OUTPUT:
        RETVAL

SV *
algorithm(Crypt::PQ::SLHDSA self)
    CODE:
    {
        const char *name;
        if (self->initialized == 0) XSRETURN_UNDEF;
        if (slhdsa_alg_name(self->key.alg, &name) != CRYPT_OK)
            croak("FATAL: unknown SLH-DSA algorithm");
        RETVAL = newSVpv(name, 0);
    }
    OUTPUT:
        RETVAL

SV*
key2hash(Crypt::PQ::SLHDSA self)
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
        if (slhdsa_alg_name(self->key.alg, &name) != CRYPT_OK)
            croak("FATAL: unknown SLH-DSA algorithm");
        not_used = hv_store(rv_hash, "alg", 3, newSVpv(name, 0), 0);
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
          not_used = hv_store(rv_hash, "priv", 4, newSVpvn(NULL, 0), 0);
        }
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
export_key_der(Crypt::PQ::SLHDSA self, char * type)
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
          rv = slhdsa_export(out, &out_len, PK_PRIVATE|PK_STD, &self->key);
          if (rv != CRYPT_OK) { Safefree(out); croak("FATAL: slhdsa_export(PK_PRIVATE|PK_STD) failed: %s", error_to_string(rv)); }
          RETVAL = newSVpvn((char*)out, out_len);
          zeromem(out, self->key.sklen + 64);
          Safefree(out);
        }
        else if (strEQ(type, "public")) {
          out_len = self->key.pklen + 64;
          Newz(0, out, out_len, unsigned char);
          if (out == NULL) croak("FATAL: Newz failed");
          rv = slhdsa_export(out, &out_len, PK_PUBLIC|PK_STD, &self->key);
          if (rv != CRYPT_OK) { Safefree(out); croak("FATAL: slhdsa_export(PK_PUBLIC|PK_STD) failed: %s", error_to_string(rv)); }
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
export_key_raw(Crypt::PQ::SLHDSA self, char * type)
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
          rv = slhdsa_export_raw(out, &out_len, PK_PRIVATE, &self->key);
          if (rv != CRYPT_OK) { Safefree(out); croak("FATAL: slhdsa_export_raw(PK_PRIVATE) failed: %s", error_to_string(rv)); }
          RETVAL = newSVpvn((char*)out, out_len);
          zeromem(out, self->key.sklen);
          Safefree(out);
        }
        else if (strEQ(type, "public")) {
          out_len = self->key.pklen;
          Newz(0, out, out_len, unsigned char);
          if (out == NULL) croak("FATAL: Newz failed");
          rv = slhdsa_export_raw(out, &out_len, PK_PUBLIC, &self->key);
          if (rv != CRYPT_OK) { Safefree(out); croak("FATAL: slhdsa_export_raw(PK_PUBLIC) failed: %s", error_to_string(rv)); }
          RETVAL = newSVpvn((char*)out, out_len);
          Safefree(out);
        }
        else {
          croak("FATAL: export_key_raw invalid type '%s'", type);
        }
    }
    OUTPUT:
        RETVAL

SV *
sign_message(Crypt::PQ::SLHDSA self, SV * msg, ...)
    CODE:
    {
        int rv;
        unsigned char *msg_ptr = NULL, *ctx_ptr = NULL, *sig = NULL;
        STRLEN msg_len = 0, ctx_len = 0;
        unsigned long sig_len;

        if (self->initialized == 0) croak("FATAL: no key loaded");
        if (self->key.type != PK_PRIVATE) croak("FATAL: not a private key");
        msg_ptr = (unsigned char *)SvPVbyte(msg, msg_len);
        if (items > 2 && SvOK(ST(2))) {
            ctx_ptr = (unsigned char *)SvPVbyte(ST(2), ctx_len);
            if (ctx_len > LTC_PQC_CTX_MAX_BYTES) croak("FATAL: context must be at most %d bytes", LTC_PQC_CTX_MAX_BYTES);
        }
        rv = slhdsa_get_sizes(self->key.alg, NULL, NULL, &sig_len, NULL, NULL);
        if (rv != CRYPT_OK) croak("FATAL: slhdsa_get_sizes failed: %s", error_to_string(rv));
        Newz(0, sig, sig_len, unsigned char);
        if (sig == NULL) croak("FATAL: Newz failed");
        cryptx_internal_pk_prng_reseed(&self->pstate, self->pindex, &self->last_pid);
        rv = slhdsa_sign(msg_ptr, (unsigned long)msg_len, sig, &sig_len,
                         ctx_ptr, (unsigned long)ctx_len,
                         &self->pstate, self->pindex, &self->key);
        if (rv != CRYPT_OK) { Safefree(sig); croak("FATAL: slhdsa_sign failed: %s", error_to_string(rv)); }
        RETVAL = newSVpvn((char*)sig, sig_len);
        Safefree(sig);
    }
    OUTPUT:
        RETVAL

SV *
sign_message_ex(Crypt::PQ::SLHDSA self, SV * msg, SV * ctx, SV * optrand)
    CODE:
    {
        int rv;
        unsigned char *msg_ptr = NULL, *ctx_ptr = NULL, *optrand_ptr = NULL, *sig = NULL;
        STRLEN msg_len = 0, ctx_len = 0, optrand_len = 0;
        unsigned long sig_len, expected_optrand_len = 0;

        if (self->initialized == 0) croak("FATAL: no key loaded");
        if (self->key.type != PK_PRIVATE) croak("FATAL: not a private key");
        if (!SvOK(optrand)) croak("FATAL: undefined optrand");
        msg_ptr = (unsigned char *)SvPVbyte(msg, msg_len);
        if (SvOK(ctx)) {
            ctx_ptr = (unsigned char *)SvPVbyte(ctx, ctx_len);
            if (ctx_len > LTC_PQC_CTX_MAX_BYTES) croak("FATAL: context must be at most %d bytes", LTC_PQC_CTX_MAX_BYTES);
        }
        optrand_ptr = (unsigned char *)SvPVbyte(optrand, optrand_len);
        rv = slhdsa_get_sizes(self->key.alg, NULL, NULL, &sig_len, &expected_optrand_len, NULL);
        if (rv != CRYPT_OK) croak("FATAL: slhdsa_get_sizes failed: %s", error_to_string(rv));
        if ((unsigned long)optrand_len != expected_optrand_len)
            croak("FATAL: SLH-DSA optrand must be exactly %lu bytes for this parameter set", expected_optrand_len);
        Newz(0, sig, sig_len, unsigned char);
        if (sig == NULL) croak("FATAL: Newz failed");
        rv = slhdsa_sign_ex(msg_ptr, (unsigned long)msg_len, sig, &sig_len,
                            ctx_ptr, (unsigned long)ctx_len,
                            optrand_ptr, (unsigned long)optrand_len, &self->key);
        if (rv != CRYPT_OK) { Safefree(sig); croak("FATAL: slhdsa_sign_ex failed: %s", error_to_string(rv)); }
        RETVAL = newSVpvn((char*)sig, sig_len);
        Safefree(sig);
    }
    OUTPUT:
        RETVAL

int
verify_message(Crypt::PQ::SLHDSA self, SV * sig, SV * msg, ...)
    CODE:
    {
        int rv, stat;
        unsigned char *sig_ptr = NULL, *msg_ptr = NULL, *ctx_ptr = NULL;
        STRLEN sig_len = 0, msg_len = 0, ctx_len = 0;

        if (self->initialized == 0) croak("FATAL: no key loaded");
        sig_ptr = (unsigned char *)SvPVbyte(sig, sig_len);
        msg_ptr = (unsigned char *)SvPVbyte(msg, msg_len);
        if (items > 3 && SvOK(ST(3))) {
            ctx_ptr = (unsigned char *)SvPVbyte(ST(3), ctx_len);
            if (ctx_len > LTC_PQC_CTX_MAX_BYTES) croak("FATAL: context must be at most %d bytes", LTC_PQC_CTX_MAX_BYTES);
        }
        RETVAL = 0;
        stat = 0;
        rv = slhdsa_verify(sig_ptr, (unsigned long)sig_len,
                           msg_ptr, (unsigned long)msg_len,
                           ctx_ptr, (unsigned long)ctx_len, &stat, &self->key);
        if (rv == CRYPT_OK && stat == 1) RETVAL = 1;
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::PQ::SLHDSA self)
    CODE:
        if (self->initialized) slhdsa_free(&self->key);
        if (self->pindex >= 0 && prng_is_valid(self->pindex) == CRYPT_OK && prng_descriptor[self->pindex].done) {
          prng_descriptor[self->pindex].done(&self->pstate);
        }
        zeromem(self, sizeof(*self));
        Safefree(self);
