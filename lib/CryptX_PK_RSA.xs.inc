MODULE = CryptX         PACKAGE = Crypt::PK::RSA

Crypt::PK::RSA
_new()
    CODE:
    {
        int rv;        
        Newz(0, RETVAL, 1, struct rsa_struct);
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
generate_key(Crypt::PK::RSA self, int key_size=256, long key_e=65537)
    CODE:
    {
        int rv;
        /* key_size is in octets */
        rv = rsa_make_key(&self->yarrow_prng_state, self->yarrow_prng_index, key_size, key_e, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: rsa_make_key failed: %s", error_to_string(rv));
        RETVAL = 1; /* xxx */
    }
    OUTPUT:
        RETVAL

int
_import(Crypt::PK::RSA self, SV * key_data)
    CODE:
    {
        int rv;
        unsigned char *data=NULL;
        STRLEN data_len=0;
        
        data = (unsigned char *)SvPVbyte(key_data, data_len);
        rsa_free(&self->key);
        rv = rsa_import(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: rsa_import failed: %s", error_to_string(rv));
        RETVAL = 1; /* xxx */
    }
    OUTPUT:
        RETVAL

int
is_private(Crypt::PK::RSA self)
    CODE:
        if (self->key.type == -1 || self->key.N == NULL) croak("FATAL: is_private failed: no key loaded");
        RETVAL = (self->key.type == PK_PRIVATE) ? 1 : 0;
    OUTPUT:
        RETVAL

int
size(Crypt::PK::RSA self)
    CODE:
        if (self->key.type == -1 || self->key.N == NULL) croak("FATAL: size failed: no key loaded");
        RETVAL = ltc_mp.unsigned_size(self->key.N);
    OUTPUT:
        RETVAL

SV *
export_key_der(Crypt::PK::RSA self, char * type)
    CODE:
    {
        int rv;
        unsigned char out[4096];
        unsigned long int out_len = 4096;
        
        RETVAL = newSVpv(NULL, 0); /* undef */
        if (strnEQ(type, "private", 7)) {
          rv = rsa_export(out, &out_len, PK_PRIVATE, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_export(PK_PRIVATE) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else if (strnEQ(type, "public", 6)) {
          rv = rsa_export(out, &out_len, PK_PUBLIC, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_export(PK_PUBLIC) failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)out, out_len);
        }
        else {
          croak("FATAL: export_key_der invalid type '%s'", type);
        }
    }
    OUTPUT:
        RETVAL

SV *
_encrypt(Crypt::PK::RSA self, SV * data, char * padding, char * oaep_hash, SV * oaep_lparam)
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
        
        RETVAL = newSVpv(NULL, 0); /* undef */
        if (strnEQ(padding, "oaep", 4)) {
          hash_id = find_hash(oaep_hash);
          if(hash_id==-1) croak("FATAL: find_hash failed for '%s'", oaep_hash);
          lparam_ptr = (unsigned char *)SvPVbyte(oaep_lparam, lparam_len);
          rv = rsa_encrypt_key_ex(data_ptr, (unsigned long)data_len, buffer, &buffer_len, lparam_ptr, (unsigned long)lparam_len,
                                  &self->yarrow_prng_state, self->yarrow_prng_index,
                                  hash_id, LTC_PKCS_1_OAEP, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_encrypt_key_ex failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)buffer, buffer_len);
        }
        else if (strnEQ(padding, "v1.5", 4)) {
          rv = rsa_encrypt_key_ex(data_ptr, (unsigned long)data_len, buffer, &buffer_len, NULL, 0,
                                  &self->yarrow_prng_state, self->yarrow_prng_index,
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
_decrypt(Crypt::PK::RSA self, SV * data, char * padding, char * oaep_hash, SV * oaep_lparam)
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
        
        RETVAL = newSVpv(NULL, 0); /* undef */
        if (strnEQ(padding, "oaep", 4)) {
          hash_id = find_hash(oaep_hash);
          if(hash_id==-1) croak("FATAL: find_hash failed for '%s'", oaep_hash);
          lparam_ptr = (unsigned char *)SvPVbyte(oaep_lparam, lparam_len);
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
_sign(Crypt::PK::RSA self, SV * data, char * padding, char * hash_name, unsigned long saltlen=12)
    CODE:
    {
        int rv, hash_id;
        unsigned char *data_ptr=NULL;
        STRLEN data_len=0;
        unsigned char buffer[1024];
        unsigned long buffer_len = 1024;
        
        data_ptr = (unsigned char *)SvPVbyte(data, data_len);
        
        RETVAL = newSVpv(NULL, 0); /* undef */
        if (strnEQ(padding, "pss", 3)) {
          hash_id = find_hash(hash_name);
          if(hash_id==-1) croak("FATAL: find_hash failed for '%s'", hash_name);
          rv = rsa_sign_hash_ex(data_ptr, (unsigned long)data_len, buffer, &buffer_len, LTC_PKCS_1_PSS,
                                &self->yarrow_prng_state, self->yarrow_prng_index,
                                hash_id, saltlen, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_sign_hash_ex failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)buffer, buffer_len);
        }
        else if (strnEQ(padding, "v1.5", 4)) {
          rv = rsa_sign_hash_ex(data_ptr, (unsigned long)data_len, buffer, &buffer_len, LTC_PKCS_1_V1_5,
                                NULL, 0, 0, saltlen, &self->key);
          if (rv != CRYPT_OK) croak("FATAL: rsa_sign_hash_ex failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char*)buffer, buffer_len);
        }
        else {
          croak("FATAL: rsa_sign invalid padding '%s'", padding);
        }
    }
    OUTPUT:
        RETVAL

int
_verify(Crypt::PK::RSA self, SV * sig, SV * data, char * padding, char * hash_name, unsigned long saltlen=12)
    CODE:
    {
        int rv, hash_id, stat;
        unsigned char *data_ptr=NULL;
        STRLEN data_len=0;
        unsigned char *sig_ptr=NULL;
        STRLEN sig_len=0;
        
        data_ptr = (unsigned char *)SvPVbyte(data, data_len);
        sig_ptr = (unsigned char *)SvPVbyte(sig, sig_len);
        
        RETVAL = 1;
        if (strnEQ(padding, "pss", 3)) {
          hash_id = find_hash(hash_name);
          if(hash_id==-1) croak("FATAL: find_hash failed for '%s'", hash_name);
          rv = rsa_verify_hash_ex(sig_ptr, (unsigned long)sig_len, data_ptr, (unsigned long)data_len, LTC_PKCS_1_PSS,
                                hash_id, saltlen, &stat, &self->key);
          if (rv != CRYPT_OK || stat != 1) RETVAL = 0;
        }
        else if (strnEQ(padding, "v1.5", 4)) {
          rv = rsa_verify_hash_ex(sig_ptr, (unsigned long)sig_len, data_ptr, (unsigned long)data_len, LTC_PKCS_1_V1_5,
                                  0, saltlen, &stat, &self->key);
          if (rv != CRYPT_OK || stat != 1) RETVAL = 0;
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
        rsa_free(&self->key);
        Safefree(self);

