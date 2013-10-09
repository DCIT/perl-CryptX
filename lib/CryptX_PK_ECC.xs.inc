MODULE = CryptX         PACKAGE = Crypt::PK::ECC

Crypt::PK::ECC
_new()
    CODE:
    {
        int rv;
        Newz(0, RETVAL, 1, struct ecc_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        RETVAL->key.type = -1;
        RETVAL->yarrow_prng_index = find_prng("yarrow");
        if(RETVAL->yarrow_prng_index==-1) croak("FATAL: find_prng('yarrow') failed");
        rv = rng_make_prng(128, RETVAL->yarrow_prng_index, &RETVAL->yarrow_prng_state, NULL);
        if (rv != CRYPT_OK) croak("FATAL: rng_make_prng failed: %s", error_to_string(rv));
    }
    OUTPUT:
        RETVAL

int
_generate_key(Crypt::PK::ECC self, int key_size=32)
    CODE:
    {
        int rv;
        rv = ecc_make_key(&self->yarrow_prng_state, self->yarrow_prng_index, key_size, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_make_key failed: %s", error_to_string(rv));
        RETVAL = 1; /* xxx */
    }
    OUTPUT:
        RETVAL

int
_import(Crypt::PK::ECC self, SV * key_data)
    CODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->key.type != -1) { ecc_free(&self->key); self->key.type = -1; }
        rv = ecc_import(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_import failed: %s", error_to_string(rv));
        RETVAL = 1; /* xxx */
    }
    OUTPUT:
        RETVAL

int
import_key_x963(Crypt::PK::ECC self, SV * key_data)
    CODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        if (self->key.type != -1) { ecc_free(&self->key); self->key.type = -1; }
        rv = ecc_ansi_x963_import(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_ansi_x963_import failed: %s", error_to_string(rv));
        RETVAL = 1; /* xxx */
    }
    OUTPUT:
        RETVAL

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
        long siz;
        char buf[20001];
        SV **not_used;
    CODE:
        if (self->key.type == -1) XSRETURN_UNDEF;
        rv_hash = newHV();
        /* =====> k */
        siz = (self->key.k) ? mp_unsigned_bin_size(self->key.k) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'k' too big number");
        }
        if (siz>0) {
          mp_tohex(self->key.k, buf);
          not_used = hv_store(rv_hash, "k", 1, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "k", 1, newSVpv("", 0), 0);
        }
        /* =====> pub_x */
        siz = (self->key.pubkey.x) ? mp_unsigned_bin_size(self->key.pubkey.x) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'pub_x' too big number");
        }
        if (siz>0) {
          mp_tohex(self->key.pubkey.x, buf);
          not_used = hv_store(rv_hash, "pub_x", 5, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "pub_x", 5, newSVpv("", 0), 0);
        }
        /* =====> pub_y */
        siz = (self->key.pubkey.y) ? mp_unsigned_bin_size(self->key.pubkey.y) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'pub_y' too big number");
        }
        if (siz>0) {
          mp_tohex(self->key.pubkey.y, buf);
          not_used = hv_store(rv_hash, "pub_y", 5, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "pub_y", 5, newSVpv("", 0), 0);
        }
        /* =====> pub_z */
        siz = (self->key.pubkey.z) ? mp_unsigned_bin_size(self->key.pubkey.z) : 0;
        if (siz>10000) {
          croak("FATAL: key2hash failed - 'pub_z' too big number");
        }
        if (siz>0) {
          mp_tohex(self->key.pubkey.z, buf);
          not_used = hv_store(rv_hash, "pub_z", 5, newSVpv(buf, strlen(buf)), 0);
        }
        else{
          not_used = hv_store(rv_hash, "pub_z", 5, newSVpv("", 0), 0);
        }
        /* =====> curve_... */
        if (self->key.idx>=0) {
          not_used = hv_store(rv_hash, "curve_name",  10, newSVpv(self->key.dp->name,  strlen(self->key.dp->name)), 0);
          not_used = hv_store(rv_hash, "curve_prime", 11, newSVpv(self->key.dp->prime, strlen(self->key.dp->prime)), 0);
          not_used = hv_store(rv_hash, "curve_B",      7, newSVpv(self->key.dp->B,     strlen(self->key.dp->B)), 0);
          not_used = hv_store(rv_hash, "curve_order", 11, newSVpv(self->key.dp->order, strlen(self->key.dp->order)), 0);
          not_used = hv_store(rv_hash, "curve_Gx",     8, newSVpv(self->key.dp->Gx,    strlen(self->key.dp->Gx)), 0);
          not_used = hv_store(rv_hash, "curve_Gy",     8, newSVpv(self->key.dp->Gy,    strlen(self->key.dp->Gy)), 0);
          not_used = hv_store(rv_hash, "curve_size",  10, newSViv(self->key.dp->size), 0);
        }
        /* =====> size */
        not_used = hv_store(rv_hash, "size", 4, newSViv(ecc_get_size(&self->key)), 0);
        /* =====> type */
        not_used = hv_store(rv_hash, "type", 4, newSViv(self->key.type), 0);
        if (not_used) not_used = NULL; /* just silence the warning: variable 'not_used' set but not used */
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

        RETVAL = newSVpvn(NULL, 0); /* undef */
        if (strnEQ(type, "private", 7)) {
          rv = ecc_export(out, &out_len, PK_PRIVATE, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: ecc_export(PK_PRIVATE) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else if (strnEQ(type, "public", 6)) {
          rv = ecc_export(out, &out_len, PK_PUBLIC, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: ecc_export(PK_PUBLIC) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else {
          croak("FATAL: export_key_der invalid type '%s'", type);
        }
    }
    OUTPUT:
        RETVAL

SV *
export_key_x963(Crypt::PK::ECC self)
    CODE:
    {
        int rv;
        unsigned char out[4096];
        unsigned long int out_len = 4096;

        rv = ecc_ansi_x963_export(&self->key, out, &out_len);
        if (rv != CRYPT_OK) croak("FATAL: ecc_ansi_x963_export failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)out, out_len);
    }
    OUTPUT:
        RETVAL

SV *
_encrypt(Crypt::PK::ECC self, SV * data, char * hash_name)
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
        rv = ecc_encrypt_key(data_ptr, (unsigned long)data_len, buffer, &buffer_len,
                             &self->yarrow_prng_state, self->yarrow_prng_index,
                             hash_id, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_encrypt_key failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)buffer, buffer_len);
    }
    OUTPUT:
        RETVAL

SV *
_decrypt(Crypt::PK::ECC self, SV * data)
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
_sign(Crypt::PK::ECC self, SV * data)
    CODE:
    {
        int rv;
        unsigned char *data_ptr=NULL;
        STRLEN data_len=0;
        unsigned char buffer[1024];
        unsigned long buffer_len = 1024;

        data_ptr = (unsigned char *)SvPVbyte(data, data_len);

        rv = ecc_sign_hash(data_ptr, (unsigned long)data_len, buffer, &buffer_len,
                           &self->yarrow_prng_state, self->yarrow_prng_index,
                           &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_sign_hash_ex failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char*)buffer, buffer_len);
    }
    OUTPUT:
        RETVAL

int
_verify(Crypt::PK::ECC self, SV * sig, SV * data)
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
        rv = ecc_verify_hash(sig_ptr, (unsigned long)sig_len, data_ptr, (unsigned long)data_len, &stat, &self->key);
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

