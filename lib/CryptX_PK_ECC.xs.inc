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
generate_key(Crypt::PK::ECC self, int key_size=32)
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
        ecc_free(&self->key);
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
        ecc_free(&self->key);
        rv = ecc_ansi_x963_import(data, (unsigned long)data_len, &self->key);
        if (rv != CRYPT_OK) croak("FATAL: ecc_ansi_x963_import failed: %s", error_to_string(rv));
        RETVAL = 1; /* xxx */
    }
    OUTPUT:
        RETVAL

int
is_private(Crypt::PK::ECC self)
    CODE:
        if (self->key.type == -1) croak("FATAL: is_private failed: no key loaded");
        RETVAL = (self->key.type == PK_PRIVATE) ? 1 : 0;
    OUTPUT:
        RETVAL

int
size(Crypt::PK::ECC self)
    CODE:
        if (self->key.type == -1) croak("FATAL: size failed: no key loaded");
        RETVAL = ecc_get_size(&self->key);
    OUTPUT:
        RETVAL

SV *
export_key_der(Crypt::PK::ECC self, char * type)
    CODE:
    {
        int rv;
        unsigned char out[4096];
        unsigned long int out_len = 4096;
        
        RETVAL = newSVpv(NULL, 0); /* undef */
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
        ecc_free(&self->key);
        Safefree(self);

