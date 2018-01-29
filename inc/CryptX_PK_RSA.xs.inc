MODULE = CryptX         PACKAGE = Crypt::PK::RSA

PROTOTYPES: DISABLE

Crypt::PK::RSA
_new(Class)
    CODE:
    {
        int rv;
        Newz(0, RETVAL, 1, struct rsa_struct);
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
generate_key(Crypt::PK::RSA self, int key_size=256, long key_e=65537)
    PPCODE:
    {
        /* key_size is in octets */
        int rv;
        /* gen the key */
        rv = rsa_make_key(&self->pstate, self->pindex, key_size, key_e, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: rsa_make_key failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_import(Crypt::PK::RSA self, SV * key_data)
    PPCODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->key.type != -1) { rsa_free(&self->key); self->key.type = -1; }
        rv = rsa_import(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: rsa_import failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_import_pkcs8(Crypt::PK::RSA self, SV * key_data, SV * passwd)
    PPCODE:
    {
        int rv;
        unsigned char *data=NULL, *pwd=NULL;
        STRLEN data_len=0, pwd_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (SvOK(passwd)) {
          pwd = (unsigned char *)SvPVbyte(passwd, pwd_len);
        }
        if (self->key.type != -1) { rsa_free(&self->key); self->key.type = -1; }
        rv = rsa_import_pkcs8(data, (unsigned long)data_len, pwd, (unsigned long)pwd_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: rsa_import_pkcs8 failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_import_x509(Crypt::PK::RSA self, SV * key_data)
    PPCODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->key.type != -1) { rsa_free(&self->key); self->key.type = -1; }
        rv = rsa_import_x509(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: rsa_import_x509 failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_import_hex(Crypt::PK::RSA self, char *N, char *e, char *d=NULL, char *p=NULL, char *q=NULL, char *dP=NULL, char *dQ=NULL, char *qP=NULL)
    PPCODE:
    {
        int rv;
        unsigned char Nbin[1024], ebin[128], dbin[1024], pbin[512], qbin[512], dPbin[512], dQbin[512], qPbin[512];
        unsigned long Nlen=sizeof(Nbin), elen=sizeof(ebin), dlen=sizeof(dbin), plen=sizeof(pbin),
                      qlen=sizeof(qbin), dPlen=sizeof(dPbin), dQlen=sizeof(dQbin), qPlen=sizeof(qPbin);

        rv = radix_to_bin(N,  16,  Nbin,  &Nlen);
        if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(N) failed: %s", error_to_string(rv));
        rv = radix_to_bin(e,  16,  ebin,  &elen);
        if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(e) failed: %s", error_to_string(rv));

        if (d && strlen(d) > 0) {
          /* private */
          rv = radix_to_bin(d,  16,  dbin,  &dlen);
          if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(d) failed: %s", error_to_string(rv));
          rv = rsa_set_key(Nbin, Nlen, ebin, elen, dbin, dlen, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_set_key failed: %s", error_to_string(rv));
        }
        else {
          /* public */
          rv = rsa_set_key(Nbin, Nlen, ebin, elen, NULL, 0, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_set_key failed: %s", error_to_string(rv));
        }

        if (p && strlen(p) > 0 && q && strlen(q) > 0) {
          /* private only */
          rv = radix_to_bin(p,  16,  pbin,  &plen);
          if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(p) failed: %s", error_to_string(rv));
          rv = radix_to_bin(q,  16,  qbin,  &qlen);
          if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(q) failed: %s", error_to_string(rv));
          rv = rsa_set_factors(pbin, plen, qbin, qlen, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_set_factors failed: %s", error_to_string(rv));
        }

        if (dP && strlen(dP) > 0 && dQ && strlen(dQ) > 0 && qP && strlen(qP) > 0) {
          /* private only */
          rv = radix_to_bin(dP, 16, dPbin, &dPlen);
          if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(dP) failed: %s", error_to_string(rv));
          rv = radix_to_bin(dQ, 16, dQbin, &dQlen);
          if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(dQ) failed: %s", error_to_string(rv));
          rv = radix_to_bin(qP, 16, qPbin, &qPlen);
          if (rv != CRYPT_OK) croak("FATAL: radix_to_bin(qP) failed: %s", error_to_string(rv));
          rv = rsa_set_crt_params(dPbin, dPlen, dQbin, dQlen, qPbin, qPlen, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_set_crt_params failed: %s", error_to_string(rv));
        }

        XPUSHs(ST(0)); /* return self */
    }

int
is_private(Crypt::PK::RSA self)
    CODE:
        if (self->key.type == -1 || self->key.N == NULL) XSRETURN_UNDEF;
        RETVAL = (self->key.type == PK_PRIVATE) ? 1 : 0;
    OUTPUT:
        RETVAL

int
size(Crypt::PK::RSA self)
    CODE:
        if (self->key.type == -1 || self->key.N == NULL) XSRETURN_UNDEF;
        RETVAL = mp_unsigned_bin_size(self->key.N);
    OUTPUT:
        RETVAL

SV*
key2hash(Crypt::PK::RSA self)
    PREINIT:
        HV *rv_hash;
        long siz, nsize;
        char buf[20001];
        SV **not_used;
    CODE:
        if (self->key.type == -1 || self->key.N == NULL) XSRETURN_UNDEF;
        nsize = mp_unsigned_bin_size(self->key.N);
        rv_hash = newHV();
        /* e */
        siz = (self->key.e) ? mp_unsigned_bin_size(self->key.e) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'e' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.e, buf, 20000, 0);
          not_used = hv_store(rv_hash, "e", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "e", 1, newSVpv("", 0), 0);
        }
        /* d */
        siz = (self->key.d) ? mp_unsigned_bin_size(self->key.d) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'd' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.d, buf, 20000, 0);
          not_used = hv_store(rv_hash, "d", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "d", 1, newSVpv("", 0), 0);
        }
        /* N */
        siz = (self->key.N) ? nsize : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'N' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.N, buf, 20000, 0);
          not_used = hv_store(rv_hash, "N", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "N", 1, newSVpv("", 0), 0);
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
        /* qP */
        siz = (self->key.qP) ? mp_unsigned_bin_size(self->key.qP) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'qP' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.qP, buf, 20000, 0);
          not_used = hv_store(rv_hash, "qP", 2, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "qP", 2, newSVpv("", 0), 0);
        }
        /* dP */
        siz = (self->key.dP) ? mp_unsigned_bin_size(self->key.dP) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'dP' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.dP, buf, 20000, 0);
          not_used = hv_store(rv_hash, "dP", 2, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "dP", 2, newSVpv("", 0), 0);
        }
        /* dQ */
        siz = (self->key.dQ) ? mp_unsigned_bin_size(self->key.dQ) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'dQ' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.dQ, buf, 20000, 0);
          not_used = hv_store(rv_hash, "dQ", 2, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "dQ", 2, newSVpv("", 0), 0);
        }
        /* size */
        not_used = hv_store(rv_hash, "size", 4, newSViv(nsize), 0);
        /* type */
        not_used = hv_store(rv_hash, "type", 4, newSViv(self->key.type), 0);
        LTC_UNUSED_PARAM(not_used);
        RETVAL = newRV_noinc((SV*)rv_hash);
    OUTPUT:
        RETVAL

SV*
export_key_der(Crypt::PK::RSA self, char * type)
    CODE:
    {
        int rv;
        unsigned char out[4096];
        unsigned long out_len = 4096;

        RETVAL = newSVpvn(NULL, 0); /* undef */
        if (strnEQ(type, "private", 7)) {
          rv = rsa_export(out, &out_len, PK_PRIVATE, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_export(PK_PRIVATE) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else if (strnEQ(type, "public", 6)) {
          rv = rsa_export(out, &out_len, PK_PUBLIC|PK_STD, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_export(PK_PUBLIC|PK_STD) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else {
          croak("FATAL: export_key_der invalid type '%s'", type);
        }
    }
    OUTPUT:
        RETVAL

SV *
encrypt(Crypt::PK::RSA self, SV * data, const char * padding = "oaep", const char * oaep_hash = "SHA1", SV * oaep_lparam = NULL)
    CODE:
    {
        int rv, hash_id;
        unsigned char *lparam_ptr=NULL;
        STRLEN lparam_len=0;
        unsigned char *data_ptr=NULL;
        STRLEN data_len=0;
        unsigned char buffer[1024];
        unsigned long buffer_len = 1024;

        data_ptr = (unsigned char *)SvPVbyte(data, data_len);

        RETVAL = newSVpvn(NULL, 0); /* undef */
        if (strnEQ(padding, "oaep", 4)) {
          hash_id = _find_hash(oaep_hash);
          if (hash_id == -1) croak("FATAL: find_hash failed for '%s'", oaep_hash);
          if (oaep_lparam) lparam_ptr = (unsigned char *)SvPVbyte(oaep_lparam, lparam_len);
          rv = rsa_encrypt_key_ex(data_ptr, (unsigned long)data_len, buffer, &buffer_len, lparam_ptr, (unsigned long)lparam_len,
                                  &self->pstate, self->pindex,
                                  hash_id, LTC_PKCS_1_OAEP, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_encrypt_key_ex failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)buffer, buffer_len);
        }
        else if (strnEQ(padding, "v1.5", 4)) {
          rv = rsa_encrypt_key_ex(data_ptr, (unsigned long)data_len, buffer, &buffer_len, NULL, 0,
                                  &self->pstate, self->pindex,
                                  0, LTC_PKCS_1_V1_5, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_encrypt_key_ex failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)buffer, buffer_len);
        }
        else if (strnEQ(padding, "none", 4)) {
          /* raw RSA */
          rv = ltc_mp.rsa_me(data_ptr, (unsigned long)data_len, buffer, &buffer_len, PK_PUBLIC, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_me failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)buffer, buffer_len);
        }
        else {
          croak("FATAL: rsa_encrypt invalid padding '%s'", padding);
        }
    }
    OUTPUT:
        RETVAL

SV *
decrypt(Crypt::PK::RSA self, SV * data, const char * padding = "oaep", const char * oaep_hash = "SHA1", SV * oaep_lparam = NULL)
    CODE:
    {
        int rv, hash_id, stat;
        unsigned char *lparam_ptr=NULL;
        STRLEN lparam_len=0;
        unsigned char *data_ptr=NULL;
        STRLEN data_len=0;
        unsigned char buffer[1024];
        unsigned long buffer_len = 1024;

        data_ptr = (unsigned char *)SvPVbyte(data, data_len);

        RETVAL = newSVpvn(NULL, 0); /* undef */
        if (strnEQ(padding, "oaep", 4)) {
          hash_id = _find_hash(oaep_hash);
          if (hash_id == -1) croak("FATAL: find_hash failed for '%s'", oaep_hash);
          if (oaep_lparam) lparam_ptr = (unsigned char *)SvPVbyte(oaep_lparam, lparam_len);
          rv = rsa_decrypt_key_ex(data_ptr, (unsigned long)data_len, buffer, &buffer_len, lparam_ptr, (unsigned long)lparam_len,
                                  hash_id, LTC_PKCS_1_OAEP, &stat, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_decrypt_key_ex failed: %s", error_to_string(rv));
          if (stat != 1) croak("FATAL: rsa_decrypt - not valid OAEP packet");
          RETVAL = newSVpvn((char*)buffer, buffer_len);
        }
        else if (strnEQ(padding, "v1.5", 4)) {
          rv = rsa_decrypt_key_ex(data_ptr, (unsigned long)data_len, buffer, &buffer_len, NULL, 0,
                                  0, LTC_PKCS_1_V1_5, &stat, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_decrypt_key_ex failed: %s", error_to_string(rv));
          if (stat != 1) croak("FATAL: rsa_decrypt - invalid");
          RETVAL = newSVpvn((char*)buffer, buffer_len);
        }
        else if (strnEQ(padding, "none", 4)) {
          /* raw RSA */
          rv = ltc_mp.rsa_me(data_ptr, (unsigned long)data_len, buffer, &buffer_len, PK_PRIVATE, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_me failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)buffer, buffer_len);
        }
        else {
          croak("FATAL: rsa_encrypt invalid padding '%s'", padding);
        }
    }
    OUTPUT:
        RETVAL

SV *
sign_hash(Crypt::PK::RSA self, SV * data, const char * hash_name = "SHA1", const char * padding = "pss", unsigned long saltlen=12)
    ALIAS:
        sign_message = 1
    CODE:
    {
        int rv, hash_id;
        unsigned char buffer[1024], tmp[MAXBLOCKSIZE], *data_ptr = NULL;
        unsigned long tmp_len = MAXBLOCKSIZE, buffer_len = 1024;
        STRLEN data_len = 0;

        data_ptr = (unsigned char *)SvPVbyte(data, data_len);
        if (ix == 1) {
          hash_id = _find_hash(hash_name);
          if (hash_id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);
          rv = hash_memory(hash_id, data_ptr, (unsigned long)data_len, tmp, &tmp_len);
          if (rv != CRYPT_OK) croak("FATAL: hash_memory failed: %s", error_to_string(rv));
          data_ptr = tmp;
          data_len = tmp_len;
        }
        if (strnEQ(padding, "pss", 3)) {
          hash_id = _find_hash(hash_name);
          if (hash_id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);
          rv = rsa_sign_hash_ex(data_ptr, (unsigned long)data_len, buffer, &buffer_len, LTC_PKCS_1_PSS,
                                &self->pstate, self->pindex,
                                hash_id, saltlen, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_sign_hash_ex failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)buffer, buffer_len);
        }
        else if (strnEQ(padding, "v1.5", 4)) {
          hash_id = _find_hash(hash_name);
          if (hash_id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);
          rv = rsa_sign_hash_ex(data_ptr, (unsigned long)data_len, buffer, &buffer_len, LTC_PKCS_1_V1_5,
                                &self->pstate, self->pindex,
                                hash_id, 0, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_sign_hash_ex failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)buffer, buffer_len);
        }
        else if (strnEQ(padding, "none", 4)) {
          /* raw RSA */
          rv = ltc_mp.rsa_me(data_ptr, (unsigned long)data_len, buffer, &buffer_len, PK_PRIVATE, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_me failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)buffer, buffer_len);
        }
        else {
          croak("FATAL: rsa_sign invalid padding '%s'", padding);
        }
    }
    OUTPUT:
        RETVAL

int
verify_hash(Crypt::PK::RSA self, SV * sig, SV * data, const char * hash_name = "SHA1", const char * padding = "pss", unsigned long saltlen = 12)
    ALIAS:
        verify_message = 1
    CODE:
    {
        int rv, hash_id, stat;
        unsigned char tmp[MAXBLOCKSIZE], buffer[1024], *data_ptr = NULL, *sig_ptr = NULL;
        unsigned long i, tmp_len = MAXBLOCKSIZE, buffer_len = 1024;
        STRLEN data_len = 0, sig_len = 0;

        data_ptr = (unsigned char *)SvPVbyte(data, data_len);
        sig_ptr = (unsigned char *)SvPVbyte(sig, sig_len);
        if (ix == 1) {
          hash_id = _find_hash(hash_name);
          if (hash_id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);
          rv = hash_memory(hash_id, data_ptr, (unsigned long)data_len, tmp, &tmp_len);
          if (rv != CRYPT_OK) croak("FATAL: hash_memory failed: %s", error_to_string(rv));
          data_ptr = tmp;
          data_len = tmp_len;
        }
        RETVAL = 1;
        stat = 0;
        if (strnEQ(padding, "pss", 3)) {
          hash_id = _find_hash(hash_name);
          if (hash_id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);
          rv = rsa_verify_hash_ex(sig_ptr, (unsigned long)sig_len, data_ptr, (unsigned long)data_len, LTC_PKCS_1_PSS,
                                hash_id, saltlen, &stat, &self->key);
          if (rv != CRYPT_OK || stat != 1) RETVAL = 0;
        }
        else if (strnEQ(padding, "v1.5", 4)) {
          hash_id = _find_hash(hash_name);
          if (hash_id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);
          rv = rsa_verify_hash_ex(sig_ptr, (unsigned long)sig_len, data_ptr, (unsigned long)data_len, LTC_PKCS_1_V1_5,
                                hash_id, 0, &stat, &self->key);
          if (rv != CRYPT_OK || stat != 1) RETVAL = 0;
        }
        else if (strnEQ(padding, "none", 4)) {
          /* raw RSA */
          Zero(buffer, buffer_len, unsigned char);
          rv = ltc_mp.rsa_me(sig_ptr, (unsigned long)sig_len, buffer, &buffer_len, PK_PUBLIC, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_me failed: %s", error_to_string(rv));
          if (data_len <= buffer_len && buffer_len > 0 && data_len > 0) {
            for (i = 0; i < buffer_len - data_len; i++) if (buffer[i] != 0) RETVAL = 0;
            if (memNE(data_ptr, buffer + buffer_len - data_len, data_len)) RETVAL = 0;
          }
          else {
            RETVAL = 0;
          }
        }
        else {
          croak("FATAL: rsa_verify invalid padding '%s'", padding);
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::PK::RSA self)
    CODE:
        if (self->key.type != -1) { rsa_free(&self->key); self->key.type = -1; }
        Safefree(self);
