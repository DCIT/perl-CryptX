MODULE = CryptX         PACKAGE = Crypt::PK::ECC

PROTOTYPES: DISABLE

Crypt::PK::ECC
_new(Class)
    CODE:
    {
        int rv;
        Newz(0, RETVAL, 1, struct ecc_struct);
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
generate_key(Crypt::PK::ECC self, SV *curve)
    PPCODE:
    {
        int rv;
        /* setup dp structure */
        rv = _ecc_set_curve_from_SV(&self->key, curve); /* croaks on error */
        if (rv != CRYPT_OK) croak("FATAL: ecc_set_curve failed: %s", error_to_string(rv));
        /* gen the key */
        rv = ecc_generate_key(&self->pstate, self->pindex, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_generate_key failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_import(Crypt::PK::ECC self, SV * key_data)
    PPCODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->key.type != -1) { ecc_free(&self->key); self->key.type = -1; }
        rv = ecc_import_openssl(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_import_openssl failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_import_old(Crypt::PK::ECC self, SV * key_data)
    PPCODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->key.type != -1) { ecc_free(&self->key); self->key.type = -1; }
        rv = ecc_import(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_import failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_import_pkcs8(Crypt::PK::ECC self, SV * key_data, SV * passwd)
    PPCODE:
    {
        int rv;
        unsigned char *data=NULL, *pwd=NULL;
        STRLEN data_len=0, pwd_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (SvOK(passwd)) {
          pwd = (unsigned char *)SvPVbyte(passwd, pwd_len);
        }
        if (self->key.type != -1) { ecc_free(&self->key); self->key.type = -1; }
        rv = ecc_import_pkcs8(data, (unsigned long)data_len, pwd, (unsigned long)pwd_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_import_pkcs8 failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
_import_x509(Crypt::PK::ECC self, SV * key_data)
    PPCODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->key.type != -1) { ecc_free(&self->key); self->key.type = -1; }
        rv = ecc_import_x509(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_import_x509 failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
import_key_raw(Crypt::PK::ECC self, SV * key_data, SV * curve)
    PPCODE:
    {
        int rv, type;
        unsigned char *data=NULL;
        STRLEN data_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->key.type != -1) { ecc_free(&self->key); self->key.type = -1; }
        /* setup dp structure */
        rv = _ecc_set_curve_from_SV(&self->key, curve); /* croaks on error */
        if (rv != CRYPT_OK) croak("FATAL: ecc_set_curve failed: %s", error_to_string(rv));
        /* import key */
        type = (data_len == (STRLEN)ecc_get_size(&self->key)) ? PK_PRIVATE : PK_PUBLIC;
        rv = ecc_set_key(data, (unsigned long)data_len, type, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_set_key failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

int
is_private(Crypt::PK::ECC self)
    CODE:
        if (self->key.type == -1) XSRETURN_UNDEF;
        RETVAL = (self->key.type == PK_PRIVATE) ? 1 : 0;
    OUTPUT:
        RETVAL

int
size(Crypt::PK::ECC self)
    CODE:
        if (self->key.type == -1) XSRETURN_UNDEF;
        RETVAL = ecc_get_size(&self->key);
    OUTPUT:
        RETVAL

SV*
key2hash(Crypt::PK::ECC self)
    PREINIT:
        HV *rv_hash;
        long siz, esize;
        char buf[20001];
        SV **not_used;
    CODE:
        if (self->key.type == -1) XSRETURN_UNDEF;
        esize = ecc_get_size(&self->key);
        rv_hash = newHV();
        /* k */
        siz = (self->key.k) ? mp_unsigned_bin_size(self->key.k) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'k' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.k, buf, 20000, esize*2);
          not_used = hv_store(rv_hash, "k", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "k", 1, newSVpv("", 0), 0);
        }
        /* pub_x */
        siz = (self->key.pubkey.x) ? mp_unsigned_bin_size(self->key.pubkey.x) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'pub_x' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.pubkey.x, buf, 20000, esize*2);
          not_used = hv_store(rv_hash, "pub_x", 5, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "pub_x", 5, newSVpv("", 0), 0);
        }
        /* pub_y */
        siz = (self->key.pubkey.y) ? mp_unsigned_bin_size(self->key.pubkey.y) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'pub_y' too big number");
        }
        if (siz>0) {
          mp_tohex_with_leading_zero(self->key.pubkey.y, buf, 20000, esize*2);
          not_used = hv_store(rv_hash, "pub_y", 5, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "pub_y", 5, newSVpv("", 0), 0);
        }
        /* curve_... */
        {
          not_used = hv_store(rv_hash, "curve_cofactor",                14, newSViv(self->key.dp.cofactor), 0);
          mp_tohex_with_leading_zero(self->key.dp.prime, buf, 20000, 0);
          not_used = hv_store(rv_hash, "curve_prime",                   11, newSVpv(buf, strlen(buf)), 0);
          mp_tohex_with_leading_zero(self->key.dp.A, buf, 20000, 0);
          not_used = hv_store(rv_hash, "curve_A",                        7, newSVpv(buf, strlen(buf)), 0);
          mp_tohex_with_leading_zero(self->key.dp.B, buf, 20000, 0);
          not_used = hv_store(rv_hash, "curve_B",                        7, newSVpv(buf, strlen(buf)), 0);
          mp_tohex_with_leading_zero(self->key.dp.order, buf, 20000, 0);
          not_used = hv_store(rv_hash, "curve_order",                   11, newSVpv(buf, strlen(buf)), 0);
          mp_tohex_with_leading_zero(self->key.dp.base.x, buf, 20000, 0);
          not_used = hv_store(rv_hash, "curve_Gx",                       8, newSVpv(buf, strlen(buf)), 0);
          mp_tohex_with_leading_zero(self->key.dp.base.y, buf, 20000, 0);
          not_used = hv_store(rv_hash, "curve_Gy",                       8, newSVpv(buf, strlen(buf)), 0);
          not_used = hv_store(rv_hash, "curve_bytes",                   11, newSViv(mp_unsigned_bin_size(self->key.dp.prime)), 0);
          not_used = hv_store(rv_hash, "curve_bits",                    10, newSViv(mp_count_bits(self->key.dp.prime)), 0);

          if (self->key.dp.oidlen > 0) {
            unsigned long i;
            HV *h;
            SV **pref, *cname;
            char *cname_ptr, *oid_ptr;
            STRLEN cname_len;

            /* OID -> "curve_oid" */
            SV *oid = newSVpv("", 0);
            for(i = 0; i < self->key.dp.oidlen - 1; i++) sv_catpvf(oid, "%lu.", self->key.dp.oid[i]);
            sv_catpvf(oid, "%lu", self->key.dp.oid[i]);
            oid_ptr = SvPVX(oid);
            not_used = hv_store(rv_hash, "curve_oid", 9, oid, 0);

            /* curve name -> "curve_name" */
            if ((h = get_hv("Crypt::PK::ECC::curve_oid2name", 0)) != NULL) {
              pref = hv_fetch(h, oid_ptr, (U32)strlen(oid_ptr), 0);
              if (pref) {
                cname_ptr = SvPV(*pref, cname_len);
                cname = newSVpv(cname_ptr, cname_len);
                cname_ptr = SvPVX(cname);
                not_used = hv_store(rv_hash, "curve_name", 10, cname, 0);
              }
            }
          }
        }
        /* size */
        not_used = hv_store(rv_hash, "size", 4, newSViv(esize), 0);
        /* type */
        not_used = hv_store(rv_hash, "type", 4, newSViv(self->key.type), 0);
        LTC_UNUSED_PARAM(not_used);
        RETVAL = newRV_noinc((SV*)rv_hash);
    OUTPUT:
        RETVAL

SV *
export_key_der(Crypt::PK::ECC self, char * type)
    CODE:
    {
        int rv;
        unsigned char out[4096];
        unsigned long int out_len = 4096;

        if (self->key.type == -1) croak("FATAL: export_key_der no key");
        if (strnEQ(type, "private_short", 16)) {
          rv = ecc_export_openssl(out, &out_len, PK_PRIVATE|PK_CURVEOID, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: ecc_export_openssl(PK_PRIVATE|PK_CURVEOID) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else if (strnEQ(type, "private_compressed", 16)) {
          rv = ecc_export_openssl(out, &out_len, PK_PRIVATE|PK_CURVEOID|PK_COMPRESSED, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: ecc_export_openssl(PK_PRIVATE|PK_CURVEOID|PK_COMPRESSED) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else if (strnEQ(type, "private", 7)) {
          rv = ecc_export_openssl(out, &out_len, PK_PRIVATE, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: ecc_export_openssl(PK_PRIVATE) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else if (strnEQ(type, "public_compressed", 15)) {
          rv = ecc_export_openssl(out, &out_len, PK_PUBLIC|PK_CURVEOID|PK_COMPRESSED, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: ecc_export_openssl(PK_PUBLIC|PK_CURVEOID|PK_COMPRESSED) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else if (strnEQ(type, "public_short", 15)) {
          rv = ecc_export_openssl(out, &out_len, PK_PUBLIC|PK_CURVEOID, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: ecc_export_openssl(PK_PUBLIC|PK_CURVEOID) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else if (strnEQ(type, "public", 6)) {
          rv = ecc_export_openssl(out, &out_len, PK_PUBLIC, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: ecc_export_openssl(PK_PUBLIC) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else {
          croak("FATAL: export_key_der invalid type '%s'", type);
        }
    }
    OUTPUT:
        RETVAL

SV *
export_key_raw(Crypt::PK::ECC self, char * type)
    CODE:
    {
        int rv;
        unsigned char out[4096];
        unsigned long int out_len = sizeof(out);

        if (self->key.type == -1) croak("FATAL: export_key_der no key");
        if (strnEQ(type, "private", 7)) {
          rv = ecc_get_key(out, &out_len, PK_PRIVATE, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: ecc_get_key(private) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else if (strnEQ(type, "public_compressed", 17)) {
          rv = ecc_get_key(out, &out_len, PK_PUBLIC|PK_COMPRESSED, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: ecc_get_key(public_compressed) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else if (strnEQ(type, "public", 6)) {
          rv = ecc_get_key(out, &out_len, PK_PUBLIC, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: ecc_get_key(public) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else {
          croak("FATAL: export_key_raw invalid type '%s'", type);
        }
    }
    OUTPUT:
        RETVAL

SV *
encrypt(Crypt::PK::ECC self, SV * data, const char * hash_name = "SHA1")
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
        rv = ecc_encrypt_key(data_ptr, (unsigned long)data_len, buffer, &buffer_len,
                             &self->pstate, self->pindex,
                             hash_id, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_encrypt_key failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)buffer, buffer_len);
    }
    OUTPUT:
        RETVAL

SV *
decrypt(Crypt::PK::ECC self, SV * data)
    CODE:
    {
        int rv;
        unsigned char *data_ptr=NULL;
        STRLEN data_len=0;
        unsigned char buffer[1024];
        unsigned long buffer_len = 1024;

        data_ptr = (unsigned char *)SvPVbyte(data, data_len);

        rv = ecc_decrypt_key(data_ptr, (unsigned long)data_len, buffer, &buffer_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_decrypt_key_ex failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)buffer, buffer_len);
    }
    OUTPUT:
        RETVAL

SV *
sign_hash(Crypt::PK::ECC self, SV * data, const char * hash_name = "SHA1")
    ALIAS:
        sign_hash_rfc7518    = 3
        sign_message         = 1
        sign_message_rfc7518 = 2
    CODE:
    {
        int rv, id;
        unsigned char buffer[1024], tmp[MAXBLOCKSIZE], *data_ptr = NULL;
        unsigned long tmp_len = MAXBLOCKSIZE, buffer_len = 1024;
        STRLEN data_len = 0;

        data_ptr = (unsigned char *)SvPVbyte(data, data_len);
        if (ix == 1 || ix == 2) {
          id = _find_hash(hash_name);
          if (id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);
          rv = hash_memory(id, data_ptr, (unsigned long)data_len, tmp, &tmp_len);
          if (rv != CRYPT_OK) croak("FATAL: hash_memory failed: %s", error_to_string(rv));
          data_ptr = tmp;
          data_len = tmp_len;
        }
        if (ix == 2 || ix == 3) {
          rv = ecc_sign_hash_rfc7518(data_ptr, (unsigned long)data_len, buffer, &buffer_len,
                             &self->pstate, self->pindex,
                             &self->key);
        }
        else {
          rv = ecc_sign_hash(data_ptr, (unsigned long)data_len, buffer, &buffer_len,
                             &self->pstate, self->pindex,
                             &self->key);
        }
        if (rv != CRYPT_OK) croak("FATAL: ecc_sign_hash_ex failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)buffer, buffer_len);
    }
    OUTPUT:
        RETVAL

int
verify_hash(Crypt::PK::ECC self, SV * sig, SV * data, const char * hash_name = "SHA1")
    ALIAS:
        verify_hash_rfc7518    = 3
        verify_message         = 1
        verify_message_rfc7518 = 2
    CODE:
    {
        int rv, stat, id;
        unsigned char tmp[MAXBLOCKSIZE], *data_ptr = NULL, *sig_ptr = NULL;
        unsigned long tmp_len = MAXBLOCKSIZE;
        STRLEN data_len = 0, sig_len = 0;

        data_ptr = (unsigned char *)SvPVbyte(data, data_len);
        sig_ptr = (unsigned char *)SvPVbyte(sig, sig_len);
        if (ix == 1 || ix == 2) {
          id = _find_hash(hash_name);
          if (id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);
          rv = hash_memory(id, data_ptr, (unsigned long)data_len, tmp, &tmp_len);
          if (rv != CRYPT_OK) croak("FATAL: hash_memory failed: %s", error_to_string(rv));
          data_ptr = tmp;
          data_len = tmp_len;
        }
        RETVAL = 1;
        stat = 0;
        if (ix == 2 || ix == 3) {
          rv = ecc_verify_hash_rfc7518(sig_ptr, (unsigned long)sig_len, data_ptr, (unsigned long)data_len, &stat, &self->key);
        }
        else {
          rv = ecc_verify_hash(sig_ptr, (unsigned long)sig_len, data_ptr, (unsigned long)data_len, &stat, &self->key);
        }
        if (rv != CRYPT_OK || stat != 1) RETVAL = 0;
    }
    OUTPUT:
        RETVAL

SV *
shared_secret(Crypt::PK::ECC self, Crypt::PK::ECC pubkey)
    CODE:
    {
        int rv;
        unsigned char buffer[1024];
        unsigned long buffer_len = 1024;

        rv = ecc_shared_secret(&self->key, &pubkey->key, buffer, &buffer_len);
        if (rv != CRYPT_OK) croak("FATAL: ecc_shared_secret failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)buffer, buffer_len);
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::PK::ECC self)
    CODE:
        if (self->key.type != -1) { ecc_free(&self->key); self->key.type = -1; }
        Safefree(self);

