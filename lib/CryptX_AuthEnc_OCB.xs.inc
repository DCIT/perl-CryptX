MODULE = CryptX       PACKAGE = Crypt::AuthEnc::OCB

Crypt::AuthEnc::OCB
_new(char * cipher_name, SV * key, SV * nonce)
    CODE:
    {
        STRLEN k_len=0;
        unsigned char *k=NULL;
        unsigned char *n=NULL;
        STRLEN n_len=0;
        int id;
        
        if (!SvPOK(key))   croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);
        if (!SvPOK(nonce)) croak("FATAL: nonce must be string/buffer scalar");
        n = (unsigned char *) SvPVbyte(nonce, n_len);

        id = find_cipher(cipher_name);
        if(id==-1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);

        Newz(0, RETVAL, 1, struct ocb_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        if (ocb3_init(&RETVAL->state, id, k, k_len, n, n_len) != CRYPT_OK) {
          croak("FATAL: ocb setup failed");
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::AuthEnc::OCB self)
    CODE:
        Safefree(self);

Crypt::AuthEnc::OCB
clone(Crypt::AuthEnc::OCB self)
    CODE:
        Newz(0, RETVAL, 1, struct ocb_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(&self->state, &RETVAL->state, 1, struct ocb_struct);
    OUTPUT:
        RETVAL

void
adata_add(Crypt::AuthEnc::OCB self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);

        if (in_data_len>0) {
          rv = ocb3_add_aad(&self->state, in_data, in_data_len);
          if (rv != CRYPT_OK) croak("FATAL: ocb3_add_aad failed: %s", error_to_string(rv)); 
        }
    }

SV *
encrypt_add(Crypt::AuthEnc::OCB self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data, *out_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        if (in_data_len==0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          RETVAL = NEWSV(0, in_data_len);
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, in_data_len);
          out_data = (unsigned char *)SvPV_nolen(RETVAL);

          if (in_data_len % (&self->state)->block_len)
            croak ("FATAL: sizeof(data) should be multiple of blocksize (%d)", (&self->state)->block_len);

          rv = ocb3_encrypt(&self->state, in_data, in_data_len, out_data);
          if (rv != CRYPT_OK) croak("FATAL: ocb3_encrypt failed: %s", error_to_string(rv)); 
        }
    }
    OUTPUT:
        RETVAL

SV *
encrypt_last(Crypt::AuthEnc::OCB self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data, *out_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);        
        if (in_data_len>0) {
          RETVAL = NEWSV(0, in_data_len);
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, in_data_len);
          out_data = (unsigned char *)SvPV_nolen(RETVAL);
        }
        else {
          RETVAL = newSVpvn("", 0);
          out_data = NULL;
        }
        rv = ocb3_encrypt_last(&self->state, in_data, in_data_len, out_data);
        if (rv != CRYPT_OK) croak("FATAL: ocb3_encrypt_last failed: %s", error_to_string(rv)); 
    }
    OUTPUT:
        RETVAL

SV *
decrypt_add(Crypt::AuthEnc::OCB self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data, *out_data;
        
        in_data = (unsigned char *)SvPVbyte(data, in_data_len);        
        if (in_data_len==0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          RETVAL = NEWSV(0, in_data_len);
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, in_data_len);
          out_data = (unsigned char *)SvPV_nolen(RETVAL);

          if (in_data_len % (&self->state)->block_len)
            croak ("FATAL: sizeof(data) should be multiple of blocksize (%d)", (&self->state)->block_len);

          rv = ocb3_decrypt(&self->state, in_data, in_data_len, out_data);
          if (rv != CRYPT_OK) croak("FATAL: ocb3_decrypt failed: %s", error_to_string(rv)); 
        }
    }
    OUTPUT:
        RETVAL

SV *
decrypt_last(Crypt::AuthEnc::OCB self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data, *out_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);        
        if (in_data_len>0) {
          RETVAL = NEWSV(0, in_data_len);
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, in_data_len);
          out_data = (unsigned char *)SvPV_nolen(RETVAL);
        }
        else {
          RETVAL = newSVpvn("", 0);
          out_data = NULL;
        }
        rv = ocb3_decrypt_last(&self->state, in_data, in_data_len, out_data);
        if (rv != CRYPT_OK) croak("FATAL: ocb3_encrypt_last failed: %s", error_to_string(rv)); 
    }
    OUTPUT:
        RETVAL

void
encrypt_done(Crypt::AuthEnc::OCB self)
    PPCODE:
    {
        int rv;
        unsigned char tag[MAXBLOCKSIZE];
        unsigned long tag_len = sizeof(tag);
                      
        rv = ocb3_done(&self->state, tag, &tag_len);
        if (rv != CRYPT_OK) croak("FATAL: ocb3_done_encrypt failed: %s", error_to_string(rv)); 

        XPUSHs(sv_2mortal(newSVpvn((char*)tag, tag_len)));
    }

void
decrypt_done(Crypt::AuthEnc::OCB self, ...)
    PPCODE:
    {
        int rv;
        unsigned char tag[MAXBLOCKSIZE];
        unsigned long tag_len = sizeof(tag);
        STRLEN expected_tag_len;
        unsigned char *expected_tag;
        
        rv = ocb3_done(&self->state, tag, &tag_len);        
        if (rv != CRYPT_OK) croak("FATAL: ocb3_done_decrypt failed: %s", error_to_string(rv));
        if (items == 1) {
          XPUSHs(sv_2mortal(newSVpvn((char*)tag, tag_len)));
        }
        else {
          if(!SvPOK(ST(1))) croak("FATAL: expected_tag must be string/buffer scalar");
          expected_tag = (unsigned char *) SvPVbyte(ST(1), expected_tag_len);
          if (expected_tag_len!=tag_len) {
            XPUSHs(sv_2mortal(newSViv(0))); /* false */
          }
          else if (memNE(expected_tag, tag, tag_len)) {
            XPUSHs(sv_2mortal(newSViv(0))); /* false */
          }
          else {
            XPUSHs(sv_2mortal(newSViv(1))); /* true */
          }          
        }
    }

int
blocksize(Crypt::AuthEnc::OCB self)
    CODE:
    {
        RETVAL = (&self->state)->block_len;
    }
    OUTPUT:
        RETVAL
