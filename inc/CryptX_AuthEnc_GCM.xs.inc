MODULE = CryptX       PACKAGE = Crypt::AuthEnc::GCM

PROTOTYPES: DISABLE

Crypt::AuthEnc::GCM
new(Class, char * cipher_name, SV * key, SV * nonce = NULL)
    CODE:
    {
        STRLEN k_len = 0, iv_len = 0;
        unsigned char *k = NULL, *iv = NULL;
        int id, rv;

        if (!SvPOK(key)) croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);
        if (nonce) {
          if (!SvPOK(nonce)) croak("FATAL: nonce must be string/buffer scalar");
          iv = (unsigned char *)SvPVbyte(nonce, iv_len);
        }

        id = _find_cipher(cipher_name);
        if (id == -1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);

        Newz(0, RETVAL, 1, gcm_state);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = gcm_init(RETVAL, id, k, (unsigned long)k_len);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: gcm_init failed: %s", error_to_string(rv));
        }

        if (iv && iv_len > 0) {
          rv = gcm_add_iv(RETVAL, iv, (unsigned long)iv_len);
          if (rv != CRYPT_OK) {
            Safefree(RETVAL);
            croak("FATAL: gcm_add_iv failed: %s", error_to_string(rv));
          }
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
        Newz(0, RETVAL, 1, gcm_state);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(self, RETVAL, 1, gcm_state);
    OUTPUT:
        RETVAL

void
reset(Crypt::AuthEnc::GCM self)
    PPCODE:
    {
        int rv;
        rv = gcm_reset(self);
        if (rv != CRYPT_OK) croak("FATAL: gcm_reset failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

SV *
encrypt_add(Crypt::AuthEnc::GCM self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data, *out_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        if (in_data_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else
        {
          RETVAL = NEWSV(0, in_data_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, in_data_len);
          out_data = (unsigned char *)SvPVX(RETVAL);
          rv = gcm_process(self, in_data, (unsigned long)in_data_len, out_data, GCM_ENCRYPT);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: encrypt_add/gcm_process failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL

void
iv_add(Crypt::AuthEnc::GCM self, SV * data)
    PPCODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        rv = gcm_add_iv(self, in_data, (unsigned long)in_data_len);
        if (rv != CRYPT_OK) croak("FATAL: gcm_add_iv failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
adata_add(Crypt::AuthEnc::GCM self, SV * data)
    PPCODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        rv = gcm_add_aad(self, in_data, (unsigned long)in_data_len);
        if (rv != CRYPT_OK) croak("FATAL: gcm_add_aad failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

SV *
decrypt_add(Crypt::AuthEnc::GCM self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data, *out_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        if (in_data_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          RETVAL = NEWSV(0, in_data_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, in_data_len);
          out_data = (unsigned char *)SvPVX(RETVAL);
          rv = gcm_process(self, out_data, (unsigned long)in_data_len, in_data, GCM_DECRYPT);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: encrypt_add/gcm_process failed: %s", error_to_string(rv));
          }
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

        rv = gcm_done(self, tag, &tag_len);
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

        rv = gcm_done(self, tag, &tag_len);
        if (rv != CRYPT_OK) croak("FATAL: gcm_done failed: %s", error_to_string(rv));
        if (items == 1) {
          XPUSHs(sv_2mortal(newSVpvn((char*)tag, tag_len)));
        }
        else {
          if (!SvPOK(ST(1))) croak("FATAL: expected_tag must be string/buffer scalar");
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

void
gcm_encrypt_authenticate(char *cipher_name, SV *key, SV *nonce, SV *header = NULL, SV *plaintext)
    PPCODE:
    {
        STRLEN k_len = 0, n_len = 0, h_len = 0, pt_len = 0;
        unsigned char *k = NULL, *n = NULL, *h = NULL, *pt = NULL;
        int rv, id;
        unsigned char tag[MAXBLOCKSIZE];
        unsigned long tag_len = sizeof(tag);
        SV *output;

        if (SvPOK(key))       k  = (unsigned char *) SvPVbyte(key, k_len);
        if (SvPOK(nonce))     n  = (unsigned char *) SvPVbyte(nonce, n_len);
        if (SvPOK(plaintext)) pt = (unsigned char *) SvPVbyte(plaintext, pt_len);
        if (SvPOK(header))    h  = (unsigned char *) SvPVbyte(header, h_len);

        id = _find_cipher(cipher_name);
        if(id==-1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);
        output = NEWSV(0, pt_len > 0 ? pt_len : 1); /* avoid zero! */
        SvPOK_only(output);
        SvCUR_set(output, pt_len);

        rv = gcm_memory(id, k, (unsigned long)k_len, n, (unsigned long)n_len, h, (unsigned long)h_len,
                        pt, (unsigned long)pt_len, (unsigned char *)SvPVX(output), tag, &tag_len, GCM_ENCRYPT);

        if (rv != CRYPT_OK) {
          SvREFCNT_dec(output);
          croak("FATAL: ccm_memory failed: %s", error_to_string(rv));
        }
        XPUSHs(sv_2mortal(output));
        XPUSHs(sv_2mortal(newSVpvn((char*)tag, tag_len)));
    }

void
gcm_decrypt_verify(char *cipher_name, SV *key, SV *nonce, SV *header, SV *ciphertext, SV *tagsv)
    PPCODE:
    {
        STRLEN k_len = 0, n_len = 0, h_len = 0, ct_len = 0, t_len = 0;
        unsigned char *k = NULL, *n = NULL, *h = NULL, *ct = NULL, *t = NULL;
        int rv, id;
        unsigned char tag[MAXBLOCKSIZE];
        unsigned long tag_len;
        SV *output;

        if (SvPOK(key))        k  = (unsigned char *) SvPVbyte(key, k_len);
        if (SvPOK(nonce))      n  = (unsigned char *) SvPVbyte(nonce, n_len);
        if (SvPOK(ciphertext)) ct = (unsigned char *) SvPVbyte(ciphertext, ct_len);
        if (SvPOK(tagsv))      t  = (unsigned char *) SvPVbyte(tagsv, t_len);
        if (SvPOK(header))     h  = (unsigned char *) SvPVbyte(header, h_len);

        id = _find_cipher(cipher_name);
        if(id==-1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);
        output = NEWSV(0, ct_len > 0 ? ct_len : 1); /* avoid zero! */
        SvPOK_only(output);
        SvCUR_set(output, ct_len);
        tag_len = (unsigned long)t_len;
        Copy(t, tag, t_len, unsigned char);

        rv = gcm_memory(id, k, (unsigned long)k_len, n, (unsigned long)n_len, h, (unsigned long)h_len,
                        (unsigned char *)SvPVX(output), (unsigned long)ct_len, ct, tag, &tag_len, GCM_DECRYPT);

        if (rv != CRYPT_OK) {
          SvREFCNT_dec(output);
          XPUSHs(sv_2mortal(newSVpvn(NULL,0))); /* undef */
        }
        else {
          XPUSHs(sv_2mortal(output));
        }
    }
