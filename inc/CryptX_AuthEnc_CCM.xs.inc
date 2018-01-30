MODULE = CryptX       PACKAGE = Crypt::AuthEnc::CCM

PROTOTYPES: DISABLE

Crypt::AuthEnc::CCM
new(Class, char * cipher_name, SV * key, SV * nonce, SV * adata, int tag_len, int pt_len)
    CODE:
    {
        unsigned char *k=NULL;
        STRLEN k_len=0;
        unsigned char *n=NULL;
        STRLEN n_len=0;
        unsigned char *h=NULL;
        STRLEN h_len=0;
        int rv, id;

        if (tag_len < 1 || tag_len > MAXBLOCKSIZE) croak("FATAL: invalid tag_len %d", tag_len);
        if (pt_len < 0)    croak("FATAL: invalid pt_len");
        if (!SvPOK(key))   croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);
        if (!SvPOK(nonce)) croak("FATAL: nonce must be string/buffer scalar");
        n = (unsigned char *) SvPVbyte(nonce, n_len);
        if (!SvPOK(adata)) croak("FATAL: adata must be string/buffer scalar");
        h = (unsigned char *) SvPVbyte(adata, h_len);

        id = _find_cipher(cipher_name);
        if (id == -1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);

        Newz(0, RETVAL, 1, ccm_state);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = ccm_init(RETVAL, id, k, (int)k_len, (int)pt_len, (int)tag_len, (int)h_len); /* XXX-TODO why int? */
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: ccm_init failed: %s", error_to_string(rv));
        }
        rv = ccm_add_nonce(RETVAL, n, (unsigned long)n_len);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: ccm_add_nonce failed: %s", error_to_string(rv));
        }
        rv = ccm_add_aad(RETVAL, h, (unsigned long)h_len);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: ccm_add_aad failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::AuthEnc::CCM self)
    CODE:
        Safefree(self);

Crypt::AuthEnc::CCM
clone(Crypt::AuthEnc::CCM self)
    CODE:
        Newz(0, RETVAL, 1, ccm_state);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(self, RETVAL, 1, ccm_state);
    OUTPUT:
        RETVAL

SV *
encrypt_add(Crypt::AuthEnc::CCM self, SV * data)
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
          rv = ccm_process(self, in_data, (unsigned long)in_data_len, out_data, CCM_ENCRYPT);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: ccm_process failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL

SV *
decrypt_add(Crypt::AuthEnc::CCM self, SV * data)
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
          rv = ccm_process(self, out_data, (unsigned long)in_data_len, in_data, CCM_DECRYPT);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: ccm_process failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL

void
encrypt_done(Crypt::AuthEnc::CCM self)
    PPCODE:
    {
        int rv;
        unsigned char tag[MAXBLOCKSIZE];
        unsigned long tag_len = MAXBLOCKSIZE;

        rv = ccm_done(self, tag, &tag_len);
        if (rv != CRYPT_OK) croak("FATAL: ccm_done failed: %s", error_to_string(rv));
        XPUSHs(sv_2mortal(newSVpvn((char*)tag, tag_len)));
    }

void
decrypt_done(Crypt::AuthEnc::CCM self, ...)
    PPCODE:
    {
        int rv;
        unsigned char tag[MAXBLOCKSIZE];
        unsigned long tag_len = MAXBLOCKSIZE;
        STRLEN expected_tag_len;
        unsigned char *expected_tag;

        rv = ccm_done(self, tag, &tag_len);
        if (rv != CRYPT_OK) croak("FATAL: ccm_done failed: %s", error_to_string(rv));
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
ccm_encrypt_authenticate(char *cipher_name, SV *key, SV *nonce, SV *header, unsigned long tag_len, SV *plaintext)
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

        rv = ccm_memory(id, k, (unsigned long)k_len, NULL, n, (unsigned long)n_len, h, (unsigned long)h_len,
                        pt, (unsigned long)pt_len, (unsigned char *)SvPVX(output), tag, &tag_len, CCM_ENCRYPT);

        if (rv != CRYPT_OK) {
          SvREFCNT_dec(output);
          croak("FATAL: ccm_memory failed: %s", error_to_string(rv));
        }
        XPUSHs(sv_2mortal(output));
        XPUSHs(sv_2mortal(newSVpvn((char*)tag, tag_len)));
    }

void
ccm_decrypt_verify(char *cipher_name, SV *key, SV *nonce, SV *header, SV *ciphertext, SV *tagsv)
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

        rv = ccm_memory(id, k, (unsigned long)k_len, NULL, n, (unsigned long)n_len, h, (unsigned long)h_len,
                        (unsigned char *)SvPVX(output), (unsigned long)ct_len, ct, tag, &tag_len, CCM_DECRYPT);

        if (rv != CRYPT_OK) {
          SvREFCNT_dec(output);
          XPUSHs(sv_2mortal(newSVpvn(NULL,0))); /* undef */
        }
        else {
          XPUSHs(sv_2mortal(output));
        }
    }
