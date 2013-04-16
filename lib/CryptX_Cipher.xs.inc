MODULE = CryptX         PACKAGE = Crypt::Cipher

Crypt::Cipher
_new(cipher_name, key, rounds=0)
        char * cipher_name
        SV * key
        int rounds
    CODE:
    {
        STRLEN key_len;
        unsigned char *key_data=NULL;
        int rv;
        int id;
        
        if (!SvPOK (key)) croak("FATAL: key must be string scalar");
        key_data = (unsigned char *)SvPVbyte(key, key_len);
        
        id = find_cipher(cipher_name);
        if(id==-1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);

        Newz(0, RETVAL, 1, struct cipher_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        RETVAL->id = id;
        RETVAL->desc = &cipher_descriptor[id];
        rv = RETVAL->desc->setup(key_data, key_len, rounds, &RETVAL->skey);
        if(rv!=CRYPT_OK) croak("FATAL: cipher setup failed: %s", error_to_string(rv));
    }
    OUTPUT:
        RETVAL

void
DESTROY(self)
        Crypt::Cipher self
    CODE:
        Safefree(self);

int
_max_keysize(self, ...)
        Crypt::Cipher self
    CODE:
        RETVAL = self->desc->max_key_length;
    OUTPUT:
        RETVAL

int
_min_keysize(self, ...)
        Crypt::Cipher self
    CODE:
        RETVAL = self->desc->min_key_length;
    OUTPUT:
        RETVAL

int
_blocksize(self, ...)
        Crypt::Cipher self
    CODE:
        RETVAL = self->desc->block_length;
    OUTPUT:
        RETVAL

int
_default_rounds(self, ...)
        Crypt::Cipher self
    CODE:
        RETVAL = self->desc->default_rounds;
    OUTPUT:
        RETVAL

SV *
encrypt(self, data)
        Crypt::Cipher self
        SV * data
    CODE:
    {
        int rv;
        STRLEN len;
        void *plaintext = SvPVbyte(data, len);

        if (len==0)
          RETVAL = newSVpvn("", 0);
        else if (len % self->desc->block_length)
          croak ("FATAL: sizeof(data) should be multiple of blocksize (%d)", self->desc->block_length);
        else {
          /* idea from Crypt::Rijndael */
          RETVAL = NEWSV(0, len);
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, len);
          rv = self->desc->ecb_encrypt((unsigned char *)plaintext, (unsigned char *)SvPV_nolen(RETVAL), &self->skey);
          if (rv!=CRYPT_OK) croak("FATAL: encrypt failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

SV *
decrypt(self, data)
        Crypt::Cipher self
        SV * data
    CODE:
    {
        int rv;
        STRLEN len;
        void *ciphertext = SvPVbyte(data, len);

        if (len==0)
          RETVAL = newSVpvn("", 0);
        else if (len % self->desc->block_length)
          croak ("FATAL: sizeof(data) should be multiple of blocksize (%d)", self->desc->block_length);
        else {
          /* idea from Crypt::Rijndael */
          RETVAL = NEWSV(0, len);
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, len);
          rv = self->desc->ecb_decrypt((unsigned char *)ciphertext, (unsigned char *)SvPV_nolen(RETVAL), &self->skey);
          if (rv!=CRYPT_OK) croak("FATAL: decrypt failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

int
_block_length_by_name(cipher_name)
        char * cipher_name
    CODE:
    {
        int rv, id;
        
        id = find_cipher(cipher_name);
        if(id==-1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);
        
        rv = cipher_descriptor[id].block_length;
        if (!rv) XSRETURN_UNDEF;
        RETVAL = rv;
    }
    OUTPUT:
        RETVAL

int
_min_key_length_by_name(cipher_name)
        char * cipher_name
    CODE:
    {
        int rv, id;
        
        id = find_cipher(cipher_name);
        if(id==-1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);
        
        rv = cipher_descriptor[id].min_key_length;
        if (!rv) XSRETURN_UNDEF;
        RETVAL = rv;
    }
    OUTPUT:
        RETVAL

int
_max_key_length_by_name(cipher_name)
        char * cipher_name
    CODE:
    {
        int rv, id;
        
        id = find_cipher(cipher_name);
        if(id==-1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);
        
        rv = cipher_descriptor[id].max_key_length;
        if (!rv) XSRETURN_UNDEF;
        RETVAL = rv;
    }
    OUTPUT:
        RETVAL

int
_default_rounds_by_name(cipher_name)
        char * cipher_name
    CODE:
    {
        int rv, id;
        
        id = find_cipher(cipher_name);
        if(id==-1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);
        
        rv = cipher_descriptor[id].default_rounds;
        if (!rv) XSRETURN_UNDEF;
        RETVAL = rv;
    }
    OUTPUT:
        RETVAL
