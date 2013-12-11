MODULE = CryptX         PACKAGE = Crypt::PK::ECC

Crypt::PK::ECC
_new()
    CODE:
    {
        int rv;
        Newz(0, RETVAL, 1, struct ecc_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        RETVAL->yarrow_prng_index = find_prng("yarrow");
        RETVAL->key.type = -1;
        RETVAL->dp.name  = NULL;
        RETVAL->dp.prime = NULL;
        RETVAL->dp.A     = NULL;
        RETVAL->dp.B     = NULL;
        RETVAL->dp.order = NULL;
        RETVAL->dp.Gx    = NULL;
        RETVAL->dp.Gy    = NULL;
        if(RETVAL->yarrow_prng_index==-1) croak("FATAL: find_prng('yarrow') failed");
        rv = rng_make_prng(128, RETVAL->yarrow_prng_index, &RETVAL->yarrow_prng_state, NULL);
        if (rv != CRYPT_OK) croak("FATAL: rng_make_prng failed: %s", error_to_string(rv));
    }
    OUTPUT:
        RETVAL

void
generate_key_old(Crypt::PK::ECC self, int key_size=32)
    PPCODE:
    {
        int rv;
        _ecc_free_key(&self->key, &self->dp);
        rv = ecc_make_key(&self->yarrow_prng_state, self->yarrow_prng_index, key_size, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_make_key failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
generate_key(Crypt::PK::ECC self, SV *param)
    PPCODE:
    {
        int rv;
        HV *h;
        SV **sv_size, **sv_name, **sv_prime, **sv_A, **sv_B, **sv_order, **sv_Gx, **sv_Gy;
        char *ch_name, *ch_prime, *ch_A, *ch_B, *ch_order, *ch_Gx, *ch_Gy;
        STRLEN l_name, l_prime, l_A, l_B, l_order, l_Gx, l_Gy;

        if (SvIOK(param)) {
          int key_size = SvIV(param);
          if (key_size<=0 || key_size>65) croak("FATAL: generate_key_ex: invalid key_size");
          _ecc_free_key(&self->key, &self->dp);
          rv = ecc_make_key(&self->yarrow_prng_state, self->yarrow_prng_index, key_size, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: ecc_make_key failed: %s", error_to_string(rv));
        }
        else if (SvROK(param)) {
          if ((h = (HV*)(SvRV(param)))              == NULL) croak("FATAL: generate_key_ex: param is not valid hashref");
          if ((sv_size  = hv_fetchs(h, "size",  0)) == NULL) croak("FATAL: generate_key_ex: missing param size");
          if ((sv_name  = hv_fetchs(h, "name",  0)) == NULL) croak("FATAL: generate_key_ex: missing param name");
          if ((sv_prime = hv_fetchs(h, "prime", 0)) == NULL) croak("FATAL: generate_key_ex: missing param prime");
          if ((sv_A     = hv_fetchs(h, "A",     0)) == NULL) croak("FATAL: generate_key_ex: missing param A");
          if ((sv_B     = hv_fetchs(h, "B",     0)) == NULL) croak("FATAL: generate_key_ex: missing param B");
          if ((sv_order = hv_fetchs(h, "order", 0)) == NULL) croak("FATAL: generate_key_ex: missing param order");
          if ((sv_Gx    = hv_fetchs(h, "Gx",    0)) == NULL) croak("FATAL: generate_key_ex: missing param Gx");
          if ((sv_Gy    = hv_fetchs(h, "Gy",    0)) == NULL) croak("FATAL: generate_key_ex: missing param Gy");

          if (!SvOK(*sv_size )) croak("FATAL: generate_key_ex: undefined param size");
          if (!SvOK(*sv_name )) croak("FATAL: generate_key_ex: undefined param name");
          if (!SvOK(*sv_prime)) croak("FATAL: generate_key_ex: undefined param prime");
          if (!SvOK(*sv_A    )) croak("FATAL: generate_key_ex: undefined param A");
          if (!SvOK(*sv_B    )) croak("FATAL: generate_key_ex: undefined param B");
          if (!SvOK(*sv_order)) croak("FATAL: generate_key_ex: undefined param order");
          if (!SvOK(*sv_Gx   )) croak("FATAL: generate_key_ex: undefined param Gx");
          if (!SvOK(*sv_Gy   )) croak("FATAL: generate_key_ex: undefined param Gy");

          self->dp.size = SvIVX(*sv_size);
          ch_name  = SvPV(*sv_name,  l_name);
          ch_prime = SvPV(*sv_prime, l_prime);
          ch_A     = SvPV(*sv_A,     l_A);
          ch_B     = SvPV(*sv_B,     l_B);
          ch_order = SvPV(*sv_order, l_order);
          ch_Gx    = SvPV(*sv_Gx,    l_Gx);
          ch_Gy    = SvPV(*sv_Gy,    l_Gy);

          _ecc_free_key(&self->key, &self->dp);
          Newz(0, (self->dp.name),  1+l_name,  char); Copy(ch_name,  self->dp.name,  l_name,  char);
          Newz(0, (self->dp.prime), 1+l_prime, char); Copy(ch_prime, self->dp.prime, l_prime, char);
          Newz(0, (self->dp.A),     1+l_A,     char); Copy(ch_A,     self->dp.A,     l_A,     char);
          Newz(0, (self->dp.B),     1+l_B,     char); Copy(ch_B,     self->dp.B,     l_B,     char);
          Newz(0, (self->dp.order), 1+l_order, char); Copy(ch_order, self->dp.order, l_order, char);
          Newz(0, (self->dp.Gx),    1+l_Gx,    char); Copy(ch_Gx,    self->dp.Gx,    l_Gx,    char);
          Newz(0, (self->dp.Gy),    1+l_Gy,    char); Copy(ch_Gy,    self->dp.Gy,    l_Gy,    char);

          rv = ecc_make_key_ex(&self->yarrow_prng_state, self->yarrow_prng_index, &self->key, &self->dp);
          if (rv != CRYPT_OK) croak("FATAL: ecc_make_key_ex failed: %s", error_to_string(rv));
        }
        else {
          croak("FATAL: generate_key_ex: param has to be integer or hashref");
        }
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
        _ecc_free_key(&self->key, &self->dp);
        rv = ecc_import(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_import failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

int
import_key_x963(Crypt::PK::ECC self, SV * key_data)
    CODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;

        data = (unsigned char *)SvPVbyte(key_data, data_len);
        _ecc_free_key(&self->key, &self->dp);
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
        if (self->key.dp) {
          not_used = hv_store(rv_hash, "curve_name",  10, newSVpv(self->key.dp->name,  strlen(self->key.dp->name)), 0);
          not_used = hv_store(rv_hash, "curve_prime", 11, newSVpv(self->key.dp->prime, strlen(self->key.dp->prime)), 0);
          not_used = hv_store(rv_hash, "curve_A",      7, newSVpv(self->key.dp->A,     strlen(self->key.dp->A)), 0);
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
        _ecc_free_key(&self->key, &self->dp);
        Safefree(self);

