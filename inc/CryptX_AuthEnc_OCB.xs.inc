MODULE = CryptX       PACKAGE = Crypt::AuthEnc::OCB

PROTOTYPES: DISABLE

Crypt::AuthEnc::OCB
new(Class, char * cipher_name, SV * key, SV * nonce, unsigned long taglen)
    CODE:
    {
        STRLEN k_len=0;
        unsigned char *k=NULL;
        unsigned char *n=NULL;
        STRLEN n_len=0;
        int rv, id;

        if (!SvPOK(key))   croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);
        if (!SvPOK(nonce)) croak("FATAL: nonce must be string/buffer scalar");
        n = (unsigned char *) SvPVbyte(nonce, n_len);

        id = _find_cipher(cipher_name);
        if (id == -1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);

        Newz(0, RETVAL, 1, ocb3_state);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = ocb3_init(RETVAL, id, k, (unsigned long)k_len, n, (unsigned long)n_len, taglen);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: ocb setup failed: %s", error_to_string(rv));
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
        Newz(0, RETVAL, 1, ocb3_state);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(self, RETVAL, 1, ocb3_state);
    OUTPUT:
        RETVAL

void
adata_add(Crypt::AuthEnc::OCB self, SV * data)
    PPCODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);

        if (in_data_len>0) {
          rv = ocb3_add_aad(self, in_data, (unsigned long)in_data_len);
          if (rv != CRYPT_OK) croak("FATAL: ocb3_add_aad failed: %s", error_to_string(rv));
        }
        XPUSHs(ST(0)); /* return self */
    }

SV *
encrypt_add(Crypt::AuthEnc::OCB self, SV * data)
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
          if (in_data_len % 16) {
            croak ("FATAL: sizeof(data) should be multiple of 16");
          }
          RETVAL = NEWSV(0, in_data_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, in_data_len);
          out_data = (unsigned char *)SvPVX(RETVAL);
          rv = ocb3_encrypt(self, in_data, (unsigned long)in_data_len, out_data);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: ocb3_encrypt failed: %s", error_to_string(rv));
          }
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
        if (in_data_len == 0) {
          rv = ocb3_encrypt_last(self, in_data, 0, NULL);
          if (rv != CRYPT_OK) {
            croak("FATAL: ocb3_encrypt_last failed: %s", error_to_string(rv));
          }
          RETVAL = newSVpvn("", 0);
        }
        else {
          RETVAL = NEWSV(0, in_data_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, in_data_len);
          out_data = (unsigned char *)SvPVX(RETVAL);
          rv = ocb3_encrypt_last(self, in_data, (unsigned long)in_data_len, out_data);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: ocb3_encrypt_last failed: %s", error_to_string(rv));
          }
        }
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
        if (in_data_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          if (in_data_len % 16) {
            croak ("FATAL: sizeof(data) should be multiple of 16");
          }
          RETVAL = NEWSV(0, in_data_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, in_data_len);
          out_data = (unsigned char *)SvPVX(RETVAL);
          rv = ocb3_decrypt(self, in_data, (unsigned long)in_data_len, out_data);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: ocb3_decrypt failed: %s", error_to_string(rv));
          }
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
        if (in_data_len == 0) {
          rv = ocb3_decrypt_last(self, in_data, 0, NULL);
          if (rv != CRYPT_OK) {
            croak("FATAL: ocb3_encrypt_last failed: %s", error_to_string(rv));
          }
          RETVAL = newSVpvn("", 0);
        }
        else {
          RETVAL = NEWSV(0, in_data_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, in_data_len);
          out_data = (unsigned char *)SvPVX(RETVAL);
          rv = ocb3_decrypt_last(self, in_data, (unsigned long)in_data_len, out_data);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: ocb3_encrypt_last failed: %s", error_to_string(rv));
          }
        }
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

        rv = ocb3_done(self, tag, &tag_len);
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

        rv = ocb3_done(self, tag, &tag_len);
        if (rv != CRYPT_OK) croak("FATAL: ocb3_done_decrypt failed: %s", error_to_string(rv));
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
ocb_encrypt_authenticate(char *cipher_name, SV *key, SV *nonce, SV *header, unsigned long tag_len, SV *plaintext)
    PPCODE:
    {
        STRLEN k_len = 0, n_len = 0, h_len = 0, pt_len = 0;
        unsigned char *k = NULL, *n = NULL, *h = NULL, *pt = NULL;
        int rv, id;
        unsigned char tag[MAXBLOCKSIZE];
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
        if(tag_len < 4 || tag_len > 16) tag_len = 16;

        rv = ocb3_encrypt_authenticate_memory(id, k, (unsigned long)k_len, n, (unsigned long)n_len,
                                              h, (unsigned long)h_len, pt, (unsigned long)pt_len,
                                              (unsigned char *)SvPVX(output), tag, &tag_len);

        if (rv != CRYPT_OK) {
          SvREFCNT_dec(output);
          croak("FATAL: ccm_memory failed: %s", error_to_string(rv));
        }
        XPUSHs(sv_2mortal(output));
        XPUSHs(sv_2mortal(newSVpvn((char*)tag, tag_len)));
    }

void
ocb_decrypt_verify(char *cipher_name, SV *key, SV *nonce, SV *header, SV *ciphertext, SV *tagsv)
    PPCODE:
    {
        STRLEN k_len = 0, n_len = 0, h_len = 0, ct_len = 0, t_len = 0;
        unsigned char *k = NULL, *n = NULL, *h = NULL, *ct = NULL, *t = NULL;
        int rv, id, stat = 0;
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

        rv = ocb3_decrypt_verify_memory(id, k, (unsigned long)k_len, n, (unsigned long)n_len,
                                        h, (unsigned long)h_len, ct, (unsigned long)ct_len,
                                        (unsigned char *)SvPVX(output), t, (unsigned long)t_len, &stat);

        if (rv != CRYPT_OK || stat != 1) {
          SvREFCNT_dec(output);
          XPUSHs(sv_2mortal(newSVpvn(NULL,0))); /* undef */
        }
        else {
          XPUSHs(sv_2mortal(output));
        }
    }
