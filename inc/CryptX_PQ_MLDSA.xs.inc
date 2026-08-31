MODULE = CryptX         PACKAGE = Crypt::PQ::MLDSA

PROTOTYPES: DISABLE

Crypt::PQ::MLDSA
_new(Class)
    CODE:
    {
        int rv;
        Newz(0, RETVAL, 1, struct cryptx_pq_mldsa_struct);
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
generate_key(Crypt::PQ::MLDSA self, char * alg_name)
    PPCODE:
    {
        int rv, alg;
        if (alg_name == NULL) croak("FATAL: undefined algorithm");
        if (mldsa_find_alg(alg_name, &alg) != CRYPT_OK)
            croak("FATAL: invalid ML-DSA algorithm '%s'", alg_name);
        if (self->initialized) {
            mldsa_free(&self->key);
            self->initialized = 0;
        }
        cryptx_internal_pk_prng_reseed(&self->pstate, self->pindex, &self->last_pid);
        rv = mldsa_make_key(&self->pstate, self->pindex, alg, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: mldsa_make_key failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
make_key_from_seed(Crypt::PQ::MLDSA self, SV * seed, char * alg_name)
    PPCODE:
    {
        int rv, alg;
        unsigned char *seed_data = NULL;
        STRLEN seed_len = 0;
        if (alg_name == NULL) croak("FATAL: undefined algorithm");
        if (mldsa_find_alg(alg_name, &alg) != CRYPT_OK)
            croak("FATAL: invalid ML-DSA algorithm '%s'", alg_name);
        if (!SvPOK_spec(seed)) croak("FATAL: seed must be string/buffer scalar");
        seed_data = (unsigned char *)SvPVbyte(seed, seed_len);
        if (seed_len != LTC_MLDSA_KEYGEN_SEED_BYTES)
            croak("FATAL: ML-DSA seed must be exactly %d bytes", LTC_MLDSA_KEYGEN_SEED_BYTES);
        if (self->initialized) {
            mldsa_free(&self->key);
            self->initialized = 0;
        }
        rv = mldsa_make_key_from_seed(alg, seed_data, (unsigned long)seed_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: mldsa_make_key_from_seed failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import(Crypt::PQ::MLDSA self, SV * key_data)
    PPCODE:
    {
        int rv;
        unsigned char *data = NULL;
        STRLEN data_len = 0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->initialized) {
            mldsa_free(&self->key);
            self->initialized = 0;
        }
        rv = mldsa_import(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: mldsa_import failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import_pkcs8(Crypt::PQ::MLDSA self, SV * key_data, SV * passwd)
    PPCODE:
    {
        int rv;
        unsigned char *data = NULL;
        STRLEN data_len = 0;
        password_ctx pw_ctx = { cryptx_internal_password_cb_getpw, cryptx_internal_password_cb_free, passwd };

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->initialized) {
            mldsa_free(&self->key);
            self->initialized = 0;
        }
        if (SvOK_spec(passwd)) {
          rv = mldsa_import_pkcs8(data, (unsigned long)data_len, &pw_ctx, &self->key);
        }
        else {
          rv = mldsa_import_pkcs8(data, (unsigned long)data_len, NULL, &self->key);
        }
        if (rv != CRYPT_OK) croak("FATAL: mldsa_import_pkcs8 failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import_pem(Crypt::PQ::MLDSA self, SV * key_data, SV * passwd)
    PPCODE:
    {
        int rv;
        unsigned char *data = NULL;
        STRLEN data_len = 0;
        password_ctx pw_ctx = { cryptx_internal_password_cb_getpw, cryptx_internal_password_cb_free, passwd };
        ltc_pka_key key_from_pem;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->initialized) {
            mldsa_free(&self->key);
            self->initialized = 0;
        }
        if (SvOK_spec(passwd)) {
          rv = pem_decode_pkcs(data, (unsigned long)data_len, &key_from_pem, &pw_ctx);
        }
        else {
          rv = pem_decode_pkcs(data, (unsigned long)data_len, &key_from_pem, NULL);
        }
        if (rv != CRYPT_OK) croak("FATAL: pem_decode_pkcs failed: %s", error_to_string(rv));
        if (key_from_pem.id != LTC_PKA_MLDSA) {
          pka_key_free(&key_from_pem);
          croak("FATAL: pem_decode_pkcs decoded non-ML-DSA key");
        }
        self->key = key_from_pem.u.mldsa;
        XMEMSET(&key_from_pem.u.mldsa, 0, sizeof(key_from_pem.u.mldsa));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
_import_x509(Crypt::PQ::MLDSA self, SV * key_data)
    PPCODE:
    {
        int rv;
        unsigned char *data = NULL;
        STRLEN data_len = 0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->initialized) {
            mldsa_free(&self->key);
            self->initialized = 0;
        }
        rv = mldsa_import_x509(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: mldsa_import_x509 failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

void
import_key_raw(Crypt::PQ::MLDSA self, SV * key, char * type, char * alg_name)
    PPCODE:
    {
        int rv, alg;
        unsigned char *key_data = NULL;
        STRLEN key_len = 0;

        if (!SvPOK_spec(key))      croak("FATAL: key must be string/buffer scalar");
        if (type == NULL)    croak("FATAL: undefined type");
        if (alg_name == NULL) croak("FATAL: undefined algorithm");
        if (mldsa_find_alg(alg_name, &alg) != CRYPT_OK)
            croak("FATAL: invalid ML-DSA algorithm '%s'", alg_name);
        key_data = (unsigned char *)SvPVbyte(key, key_len);
        if (self->initialized) {
            mldsa_free(&self->key);
            self->initialized = 0;
        }
        if (strEQ(type, "public")) {
          rv = mldsa_import_raw(key_data, (unsigned long)key_len, PK_PUBLIC, alg, &self->key);
        }
        else if (strEQ(type, "private")) {
          rv = mldsa_import_raw(key_data, (unsigned long)key_len, PK_PRIVATE, alg, &self->key);
        }
        else {
          croak("FATAL: invalid key type '%s'", type);
        }
        if (rv != CRYPT_OK) croak("FATAL: mldsa_import_raw failed: %s", error_to_string(rv));
        self->initialized = 1;
        XPUSHs(ST(0)); /* return self */
    }

int
is_private(Crypt::PQ::MLDSA self)
    CODE:
        if (self->initialized == 0) XSRETURN_UNDEF;
        RETVAL = (self->key.type == PK_PRIVATE) ? 1 : 0;
    OUTPUT:
        RETVAL

int
has_seed(Crypt::PQ::MLDSA self)
    CODE:
        if (self->initialized == 0) XSRETURN_UNDEF;
        RETVAL = mldsa_has_seed(&self->key) ? 1 : 0;
    OUTPUT:
        RETVAL

SV *
algorithm(Crypt::PQ::MLDSA self)
    CODE:
    {
        const char *name;
        if (self->initialized == 0) XSRETURN_UNDEF;
        if (mldsa_alg_name(self->key.alg, &name) != CRYPT_OK)
            croak("FATAL: unknown ML-DSA algorithm");
        RETVAL = newSVpv(name, 0);
    }
    OUTPUT:
        RETVAL

void
supported_algorithms(SV * param = NULL)
    PPCODE:
    {
        int alg;
        const char *name;
        LTC_UNUSED_PARAM(param);
        /* Parameter-set ids form a contiguous enum today, but scan a fixed range
           rather than stopping at the first gap so that sets added by a later
           libtomcrypt are picked up automatically. */
        for (alg = 0; alg < 256; alg++) {
          if (mldsa_alg_name(alg, &name) != CRYPT_OK) continue;
          XPUSHs(sv_2mortal(newSVpv(name, 0)));
        }
    }

SV*
sizes(SV * param, char * alg_name = NULL)
    PREINIT:
        HV *rv_hash;
        SV **not_used;
        unsigned long pk_sz, sk_sz, sig_sz, rnd_sz, mu_sz, ks_sz;
        int rv, alg;
    CODE:
    {
        if (sv_isobject(param) && sv_derived_from(param, "Crypt::PQ::MLDSA")) {
          IV tmp = SvIV((SV*)SvRV(param));
          Crypt__PQ__MLDSA self = INT2PTR(Crypt__PQ__MLDSA, tmp);
          if (self->initialized == 0) XSRETURN_UNDEF;
          alg = self->key.alg;
        }
        else {
          STRLEN plen;
          char *name = (SvPOK_spec(param) && !sv_derived_from(param, "Crypt::PQ::MLDSA")) ? SvPVbyte(param, plen) : alg_name;
          if (name == NULL) croak("FATAL: undefined algorithm");
          if (mldsa_find_alg(name, &alg) != CRYPT_OK)
            croak("FATAL: invalid ML-DSA algorithm '%s'", name);
        }
        rv = mldsa_get_sizes(alg, &pk_sz, &sk_sz, &sig_sz, &rnd_sz, &mu_sz, &ks_sz);
        if (rv != CRYPT_OK) croak("FATAL: mldsa_get_sizes failed: %s", error_to_string(rv));
        rv_hash = newHV();
        not_used = hv_store(rv_hash, "public_key",  10, newSVuv((UV)pk_sz),  0);
        not_used = hv_store(rv_hash, "private_key", 11, newSVuv((UV)sk_sz),  0);
        not_used = hv_store(rv_hash, "signature",    9, newSVuv((UV)sig_sz), 0);
        not_used = hv_store(rv_hash, "keygen_seed", 11, newSVuv((UV)ks_sz),  0);
        not_used = hv_store(rv_hash, "rnd",          3, newSVuv((UV)rnd_sz), 0);
        not_used = hv_store(rv_hash, "mu",           2, newSVuv((UV)mu_sz),  0);
        LTC_UNUSED_PARAM(not_used);
        RETVAL = newRV_noinc((SV*)rv_hash);
    }
    OUTPUT:
        RETVAL

SV*
key2hash(Crypt::PQ::MLDSA self)
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
        if (mldsa_alg_name(self->key.alg, &name) != CRYPT_OK)
            croak("FATAL: unknown ML-DSA algorithm");
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
        if (mldsa_has_seed(&self->key)) {
          needed = sizeof(self->key.seed) * 2 + 1;
          Newz(0, buf, needed, char);
          if (buf == NULL) croak("FATAL: Newz failed");
          blen = needed;
          rv = base16_encode(self->key.seed, sizeof(self->key.seed), buf, &blen, 0);
          if (rv != CRYPT_OK) { Safefree(buf); croak("FATAL: base16_encode failed: %s", error_to_string(rv)); }
          not_used = hv_store(rv_hash, "seed", 4, newSVpv(buf, blen), 0);
          Safefree(buf); buf = NULL;
        }
        else {
          not_used = hv_store(rv_hash, "seed", 4, newSVpvn(NULL, 0), 0);
        }
        LTC_UNUSED_PARAM(not_used);
        RETVAL = newRV_noinc((SV*)rv_hash);
    OUTPUT:
        RETVAL

SV*
export_key_der(Crypt::PQ::MLDSA self, char * type)
    CODE:
    {
        int rv;
        unsigned long out_len;
        unsigned char *out = NULL;

        if (self->initialized == 0) XSRETURN_UNDEF;
        if (strnEQ(type, "private", 7)) {
          enum ltc_pqc_privkey_format fmt;
          unsigned long alloc_len;

          if      (strEQ(type, "private"))          fmt = LTC_PQC_PRIVKEY_AUTO;
          else if (strEQ(type, "private_seed"))     fmt = LTC_PQC_PRIVKEY_SEED;
          else if (strEQ(type, "private_expanded")) fmt = LTC_PQC_PRIVKEY_EXPANDED;
          else if (strEQ(type, "private_both"))     fmt = LTC_PQC_PRIVKEY_BOTH;
          else croak("FATAL: export_key_der invalid type '%s'", type);

          if ((fmt == LTC_PQC_PRIVKEY_SEED || fmt == LTC_PQC_PRIVKEY_BOTH) && !mldsa_has_seed(&self->key))
            croak("FATAL: export_key_der('%s') needs a key with a seed, use 'private_expanded'", type);

          /* 'private_both' carries the seed as well, so budget for it */
          alloc_len = self->key.sklen + (unsigned long)sizeof(self->key.seed) + 64;
          out_len = alloc_len;
          Newz(0, out, out_len, unsigned char);
          if (out == NULL) croak("FATAL: Newz failed");
          rv = mldsa_export_ex(out, &out_len, PK_PRIVATE|PK_STD, fmt, &self->key);
          if (rv != CRYPT_OK) { zeromem(out, alloc_len); Safefree(out); croak("FATAL: mldsa_export_ex(PK_PRIVATE|PK_STD) failed: %s", error_to_string(rv)); }
          RETVAL = newSVpvn((char*)out, out_len);
          zeromem(out, alloc_len);
          Safefree(out);
        }
        else if (strEQ(type, "public")) {
          out_len = self->key.pklen + 64;
          Newz(0, out, out_len, unsigned char);
          if (out == NULL) croak("FATAL: Newz failed");
          rv = mldsa_export(out, &out_len, PK_PUBLIC|PK_STD, &self->key);
          if (rv != CRYPT_OK) { Safefree(out); croak("FATAL: mldsa_export(PK_PUBLIC|PK_STD) failed: %s", error_to_string(rv)); }
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
export_key_raw(Crypt::PQ::MLDSA self, char * type)
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
          rv = mldsa_export_raw(out, &out_len, PK_PRIVATE, &self->key);
          if (rv != CRYPT_OK) { Safefree(out); croak("FATAL: mldsa_export_raw(PK_PRIVATE) failed: %s", error_to_string(rv)); }
          RETVAL = newSVpvn((char*)out, out_len);
          zeromem(out, self->key.sklen);
          Safefree(out);
        }
        else if (strEQ(type, "public")) {
          out_len = self->key.pklen;
          Newz(0, out, out_len, unsigned char);
          if (out == NULL) croak("FATAL: Newz failed");
          rv = mldsa_export_raw(out, &out_len, PK_PUBLIC, &self->key);
          if (rv != CRYPT_OK) { Safefree(out); croak("FATAL: mldsa_export_raw(PK_PUBLIC) failed: %s", error_to_string(rv)); }
          RETVAL = newSVpvn((char*)out, out_len);
          Safefree(out);
        }
        else if (strEQ(type, "seed")) {
          unsigned char seed[sizeof(self->key.seed)];
          unsigned long seed_len = (unsigned long)sizeof(seed);

          if (!mldsa_has_seed(&self->key)) croak("FATAL: this key has no seed");
          rv = mldsa_export_seed(seed, &seed_len, &self->key);
          if (rv != CRYPT_OK) { zeromem(seed, sizeof(seed)); croak("FATAL: mldsa_export_seed failed: %s", error_to_string(rv)); }
          RETVAL = newSVpvn((char*)seed, seed_len);
          zeromem(seed, sizeof(seed));
        }
        else {
          croak("FATAL: export_key_raw invalid type '%s'", type);
        }
    }
    OUTPUT:
        RETVAL

SV *
sign_message(Crypt::PQ::MLDSA self, SV * msg, ...)
    CODE:
    {
        int rv;
        unsigned char *msg_ptr = NULL, *ctx_ptr = NULL, *sig = NULL;
        STRLEN msg_len = 0, ctx_len = 0;
        unsigned long sig_len;

        if (self->initialized == 0) croak("FATAL: no key loaded");
        if (self->key.type != PK_PRIVATE) croak("FATAL: not a private key");
        msg_ptr = (unsigned char *)SvPVbyte(msg, msg_len);
        if (items > 2 && SvOK_spec(ST(2))) {
            ctx_ptr = (unsigned char *)SvPVbyte(ST(2), ctx_len);
            if (ctx_len > LTC_PQC_CTX_MAX_BYTES) croak("FATAL: context must be at most %d bytes", LTC_PQC_CTX_MAX_BYTES);
        }
        rv = mldsa_get_sizes(self->key.alg, NULL, NULL, &sig_len, NULL, NULL, NULL);
        if (rv != CRYPT_OK) croak("FATAL: mldsa_get_sizes failed: %s", error_to_string(rv));
        Newz(0, sig, sig_len, unsigned char);
        if (sig == NULL) croak("FATAL: Newz failed");
        cryptx_internal_pk_prng_reseed(&self->pstate, self->pindex, &self->last_pid);
        rv = mldsa_sign(msg_ptr, (unsigned long)msg_len, sig, &sig_len,
                        ctx_ptr, (unsigned long)ctx_len,
                        &self->pstate, self->pindex, &self->key);
        if (rv != CRYPT_OK) { Safefree(sig); croak("FATAL: mldsa_sign failed: %s", error_to_string(rv)); }
        RETVAL = newSVpvn((char*)sig, sig_len);
        Safefree(sig);
    }
    OUTPUT:
        RETVAL

SV *
sign_message_ex_mu(Crypt::PQ::MLDSA self, SV * mu, SV * rnd)
    CODE:
    {
        int rv;
        unsigned char *mu_ptr = NULL, *rnd_ptr = NULL, *sig = NULL;
        STRLEN mu_len = 0, rnd_len = 0;
        unsigned long sig_len;

        if (self->initialized == 0) croak("FATAL: no key loaded");
        if (self->key.type != PK_PRIVATE) croak("FATAL: not a private key");
        if (!SvPOK_spec(mu))  croak("FATAL: mu must be string/buffer scalar");
        if (!SvPOK_spec(rnd)) croak("FATAL: rnd must be string/buffer scalar");
        mu_ptr  = (unsigned char *)SvPVbyte(mu,  mu_len);
        rnd_ptr = (unsigned char *)SvPVbyte(rnd, rnd_len);
        if (mu_len  != LTC_MLDSA_MU_BYTES)
            croak("FATAL: ML-DSA mu must be exactly %d bytes", LTC_MLDSA_MU_BYTES);
        if (rnd_len != LTC_MLDSA_RND_BYTES)
            croak("FATAL: ML-DSA rnd must be exactly %d bytes", LTC_MLDSA_RND_BYTES);
        rv = mldsa_get_sizes(self->key.alg, NULL, NULL, &sig_len, NULL, NULL, NULL);
        if (rv != CRYPT_OK) croak("FATAL: mldsa_get_sizes failed: %s", error_to_string(rv));
        Newz(0, sig, sig_len, unsigned char);
        if (sig == NULL) croak("FATAL: Newz failed");
        rv = mldsa_sign_ex_mu(mu_ptr,  (unsigned long)mu_len, sig, &sig_len,
                              rnd_ptr, (unsigned long)rnd_len, &self->key);
        if (rv != CRYPT_OK) { Safefree(sig); croak("FATAL: mldsa_sign_ex_mu failed: %s", error_to_string(rv)); }
        RETVAL = newSVpvn((char*)sig, sig_len);
        Safefree(sig);
    }
    OUTPUT:
        RETVAL

SV *
sign_message_ex(Crypt::PQ::MLDSA self, SV * msg, SV * ctx, SV * rnd)
    CODE:
    {
        int rv;
        unsigned char *msg_ptr = NULL, *ctx_ptr = NULL, *rnd_ptr = NULL, *sig = NULL;
        STRLEN msg_len = 0, ctx_len = 0, rnd_len = 0;
        unsigned long sig_len;

        if (self->initialized == 0) croak("FATAL: no key loaded");
        if (self->key.type != PK_PRIVATE) croak("FATAL: not a private key");
        if (!SvPOK_spec(rnd)) croak("FATAL: rnd must be string/buffer scalar");
        msg_ptr = (unsigned char *)SvPVbyte(msg, msg_len);
        if (SvOK_spec(ctx)) {
            ctx_ptr = (unsigned char *)SvPVbyte(ctx, ctx_len);
            if (ctx_len > LTC_PQC_CTX_MAX_BYTES) croak("FATAL: context must be at most %d bytes", LTC_PQC_CTX_MAX_BYTES);
        }
        rnd_ptr = (unsigned char *)SvPVbyte(rnd, rnd_len);
        if (rnd_len != LTC_MLDSA_RND_BYTES)
            croak("FATAL: ML-DSA rnd must be exactly %d bytes", LTC_MLDSA_RND_BYTES);
        rv = mldsa_get_sizes(self->key.alg, NULL, NULL, &sig_len, NULL, NULL, NULL);
        if (rv != CRYPT_OK) croak("FATAL: mldsa_get_sizes failed: %s", error_to_string(rv));
        Newz(0, sig, sig_len, unsigned char);
        if (sig == NULL) croak("FATAL: Newz failed");
        rv = mldsa_sign_ex(msg_ptr, (unsigned long)msg_len, sig, &sig_len,
                           ctx_ptr, (unsigned long)ctx_len,
                           rnd_ptr, (unsigned long)rnd_len, &self->key);
        if (rv != CRYPT_OK) { Safefree(sig); croak("FATAL: mldsa_sign_ex failed: %s", error_to_string(rv)); }
        RETVAL = newSVpvn((char*)sig, sig_len);
        Safefree(sig);
    }
    OUTPUT:
        RETVAL

SV *
compute_mu(Crypt::PQ::MLDSA self, SV * msg, SV * ctx = NULL)
    CODE:
    {
        int rv;
        unsigned char *msg_ptr = NULL, *ctx_ptr = NULL;
        STRLEN msg_len = 0, ctx_len = 0;
        unsigned char mu[LTC_MLDSA_MU_BYTES];
        unsigned long mu_len = sizeof(mu);

        if (self->initialized == 0) croak("FATAL: no key loaded");
        msg_ptr = (unsigned char *)SvPVbyte(msg, msg_len);
        if (SvOK_spec(ctx)) {
            ctx_ptr = (unsigned char *)SvPVbyte(ctx, ctx_len);
            if (ctx_len > LTC_PQC_CTX_MAX_BYTES) croak("FATAL: context must be at most %d bytes", LTC_PQC_CTX_MAX_BYTES);
        }
        rv = mldsa_compute_mu(mu, &mu_len, msg_ptr, (unsigned long)msg_len,
                              ctx_ptr, (unsigned long)ctx_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: mldsa_compute_mu failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)mu, mu_len);
    }
    OUTPUT:
        RETVAL

SV *
sign_mu(Crypt::PQ::MLDSA self, SV * mu)
    CODE:
    {
        int rv;
        unsigned char *mu_ptr = NULL, *sig = NULL;
        STRLEN mu_len = 0;
        unsigned long sig_len;
        unsigned char rnd[LTC_MLDSA_RND_BYTES];

        if (self->initialized == 0) croak("FATAL: no key loaded");
        if (self->key.type != PK_PRIVATE) croak("FATAL: not a private key");
        if (!SvPOK_spec(mu)) croak("FATAL: mu must be string/buffer scalar");
        mu_ptr = (unsigned char *)SvPVbyte(mu, mu_len);
        if (mu_len != LTC_MLDSA_MU_BYTES)
            croak("FATAL: ML-DSA mu must be exactly %d bytes", LTC_MLDSA_MU_BYTES);
        rv = mldsa_get_sizes(self->key.alg, NULL, NULL, &sig_len, NULL, NULL, NULL);
        if (rv != CRYPT_OK) croak("FATAL: mldsa_get_sizes failed: %s", error_to_string(rv));
        /* hedged signing: rnd comes from the same PRNG that sign_message uses */
        cryptx_internal_pk_prng_reseed(&self->pstate, self->pindex, &self->last_pid);
        /* parenthesised: XSUB.h maps read -> PerlLIO_read on Windows (PERL_IMPLICIT_SYS),
           which would otherwise rewrite this struct member. Same idiom as CryptX_PRNG.xs.inc. */
        if ((prng_descriptor[self->pindex].read)(rnd, sizeof(rnd), &self->pstate) != sizeof(rnd))
            croak("FATAL: PRNG read failed");
        Newz(0, sig, sig_len, unsigned char);
        if (sig == NULL) { zeromem(rnd, sizeof(rnd)); croak("FATAL: Newz failed"); }
        rv = mldsa_sign_ex_mu(mu_ptr, (unsigned long)mu_len, sig, &sig_len,
                              rnd, (unsigned long)sizeof(rnd), &self->key);
        zeromem(rnd, sizeof(rnd));
        if (rv != CRYPT_OK) { Safefree(sig); croak("FATAL: mldsa_sign_ex_mu failed: %s", error_to_string(rv)); }
        RETVAL = newSVpvn((char*)sig, sig_len);
        Safefree(sig);
    }
    OUTPUT:
        RETVAL

int
verify_mu(Crypt::PQ::MLDSA self, SV * sig, SV * mu)
    CODE:
    {
        int rv, stat;
        unsigned char *sig_ptr = NULL, *mu_ptr = NULL;
        STRLEN sig_len = 0, mu_len = 0;

        if (self->initialized == 0) croak("FATAL: no key loaded");
        sig_ptr = (unsigned char *)SvPVbyte(sig, sig_len);
        mu_ptr  = (unsigned char *)SvPVbyte(mu,  mu_len);
        RETVAL = 0;
        stat = 0;
        rv = mldsa_verify_mu(sig_ptr, (unsigned long)sig_len,
                             mu_ptr,  (unsigned long)mu_len, &stat, &self->key);
        if (rv == CRYPT_OK && stat == 1) RETVAL = 1;
    }
    OUTPUT:
        RETVAL

int
verify_message(Crypt::PQ::MLDSA self, SV * sig, SV * msg, ...)
    CODE:
    {
        int rv, stat;
        unsigned char *sig_ptr = NULL, *msg_ptr = NULL, *ctx_ptr = NULL;
        STRLEN sig_len = 0, msg_len = 0, ctx_len = 0;

        if (self->initialized == 0) croak("FATAL: no key loaded");
        sig_ptr = (unsigned char *)SvPVbyte(sig, sig_len);
        msg_ptr = (unsigned char *)SvPVbyte(msg, msg_len);
        if (items > 3 && SvOK_spec(ST(3))) {
            ctx_ptr = (unsigned char *)SvPVbyte(ST(3), ctx_len);
            if (ctx_len > LTC_PQC_CTX_MAX_BYTES) croak("FATAL: context must be at most %d bytes", LTC_PQC_CTX_MAX_BYTES);
        }
        RETVAL = 0;
        stat = 0;
        rv = mldsa_verify(sig_ptr, (unsigned long)sig_len,
                          msg_ptr, (unsigned long)msg_len,
                          ctx_ptr, (unsigned long)ctx_len, &stat, &self->key);
        if (rv == CRYPT_OK && stat == 1) RETVAL = 1;
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::PQ::MLDSA self)
    CODE:
        if (self->initialized) mldsa_free(&self->key);
        if (self->pindex >= 0 && prng_is_valid(self->pindex) == CRYPT_OK && prng_descriptor[self->pindex].done) {
          prng_descriptor[self->pindex].done(&self->pstate);
        }
        zeromem(self, sizeof(*self));
        Safefree(self);
