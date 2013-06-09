MODULE = CryptX       PACKAGE = Crypt::AuthEnc::GCM

Crypt::AuthEnc::GCM
_new(char * cipher_name, SV * key)
    CODE:
    {
        STRLEN k_len=0;
        unsigned char *k=NULL;
        int id;
        
        if (!SvPOK(key))   croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);


        id = find_cipher(cipher_name);
        if(id==-1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);

        Newz(0, RETVAL, 1, struct gcm_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        if (gcm_init(&RETVAL->state, id, k, (unsigned long)k_len) != CRYPT_OK) {
          croak("FATAL: gcm setup failed");
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::AuthEnc::GCM self)
    CODE:
        Safefree(self);

Crypt::AuthEnc::GCM
clone(Crypt::AuthEnc::GCM self)
    CODE:
        Newz(0, RETVAL, 1, struct gcm_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(&self->state, &RETVAL->state, 1, struct gcm_struct);
    OUTPUT:
        RETVAL

int
reset(Crypt::AuthEnc::GCM self)
    CODE:
    {
        int rv;
        rv = gcm_reset(&self->state);
        if (rv != CRYPT_OK) croak("FATAL: gcm_reset failed: %s", error_to_string(rv)); 
        RETVAL = rv;
    }
    OUTPUT:
        RETVAL

SV *
encrypt_add(Crypt::AuthEnc::GCM self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data, *out_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        if (in_data_len==0) {
          RETVAL = newSVpvn("", 0);
        }
        else 
        {
          RETVAL = NEWSV(0, in_data_len);
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, in_data_len);
          out_data = (unsigned char *)SvPV_nolen(RETVAL);
          rv = gcm_process(&self->state, in_data, (unsigned long)in_data_len, out_data, GCM_ENCRYPT);
          if (rv != CRYPT_OK) croak("FATAL: encrypt_add/gcm_process failed: %s", error_to_string(rv)); 
        }
    }
    OUTPUT:
        RETVAL

int
iv_add(Crypt::AuthEnc::GCM self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        rv = gcm_add_iv(&self->state, in_data, (unsigned long)in_data_len);
        if (rv != CRYPT_OK) croak("FATAL: gcm_add_iv failed: %s", error_to_string(rv)); 
        RETVAL = rv;
    }
    OUTPUT:
        RETVAL

int
adata_add(Crypt::AuthEnc::GCM self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        rv = gcm_add_aad(&self->state, in_data, (unsigned long)in_data_len);
        if (rv != CRYPT_OK) croak("FATAL: gcm_add_aad failed: %s", error_to_string(rv)); 
        RETVAL = rv;
    }
    OUTPUT:
        RETVAL

SV *
decrypt_add(Crypt::AuthEnc::GCM self, SV * data)
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
          rv = gcm_process(&self->state, out_data, (unsigned long)in_data_len, in_data, GCM_DECRYPT);
          if (rv != CRYPT_OK) croak("FATAL: encrypt_add/gcm_process failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL


void
encrypt_done(Crypt::AuthEnc::GCM self)
    PPCODE:
    {
        int rv;
        unsigned char tag[MAXBLOCKSIZE];
        unsigned long tag_len = sizeof(tag);
        
        rv = gcm_done(&self->state, tag, &tag_len);
        if (rv != CRYPT_OK) croak("FATAL: gcm_done failed: %s", error_to_string(rv));
        XPUSHs(sv_2mortal(newSVpvn((char*)tag, tag_len)));
    }

void
decrypt_done(Crypt::AuthEnc::GCM self, ...)
    PPCODE:
    {
        int rv;
        unsigned char tag[MAXBLOCKSIZE];
        unsigned long tag_len = sizeof(tag);
        STRLEN expected_tag_len;
        unsigned char *expected_tag;
        
        rv = gcm_done(&self->state, tag, &tag_len);
        if (rv != CRYPT_OK) croak("FATAL: gcm_done failed: %s", error_to_string(rv));
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
