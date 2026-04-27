MODULE = CryptX       PACKAGE = Crypt::AuthEnc::ChaCha20Poly1305

PROTOTYPES: DISABLE

Crypt::AuthEnc::ChaCha20Poly1305
new(Class, SV * key, SV * nonce = NULL)
    CODE:
    {
        int rv;
        STRLEN iv_len=0, k_len=0;
        unsigned char *iv=NULL, *k=NULL;

        if (!SvPOK_spec(key))   croak("FATAL: key must be string/buffer scalar");
        k  = (unsigned char *) SvPVbyte(key, k_len);
        if (nonce) {
          if (!SvPOK_spec(nonce)) croak("FATAL: nonce must be string/buffer scalar");
          iv = (unsigned char *) SvPVbyte(nonce, iv_len);
        }

        Newz(0, RETVAL, 1, struct cryptx_authenc_chacha20poly1305_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = chacha20poly1305_init(&RETVAL->state, k, (unsigned long)k_len);
        if (rv != CRYPT_OK) {
          zeromem(RETVAL, sizeof(*RETVAL));
          Safefree(RETVAL);
          croak("FATAL: chacha20poly1305_init failed: %s", error_to_string(rv));
        }

        if (iv && iv_len > 0) {
          rv = chacha20poly1305_setiv(&RETVAL->state, iv, (unsigned long)iv_len);
          if (rv != CRYPT_OK) {
            zeromem(RETVAL, sizeof(*RETVAL));
            Safefree(RETVAL);
            croak("FATAL: chacha20poly1305_setiv failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::AuthEnc::ChaCha20Poly1305 self)
    CODE:
        if (self) {
          zeromem(self, sizeof(*self));
          Safefree(self);
        }

Crypt::AuthEnc::ChaCha20Poly1305
clone(Crypt::AuthEnc::ChaCha20Poly1305 self)
    CODE:
        Newz(0, RETVAL, 1, struct cryptx_authenc_chacha20poly1305_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(self, RETVAL, 1, struct cryptx_authenc_chacha20poly1305_struct);
    OUTPUT:
        RETVAL

void
set_iv(Crypt::AuthEnc::ChaCha20Poly1305 self, SV * nonce)
    PPCODE:
    {
        int rv;
        STRLEN iv_len=0;
        unsigned char *iv=NULL;

        if (!SvPOK_spec(nonce)) croak("FATAL: nonce must be string/buffer scalar");
        iv = (unsigned char *) SvPVbyte(nonce, iv_len);
        if (self->finalized) croak("FATAL: AEAD object already finalized");
        rv = chacha20poly1305_setiv(&self->state, iv, (unsigned long)iv_len);
        if (rv != CRYPT_OK) croak("FATAL: chacha20poly1305_setiv failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */;
    }

void
set_iv_rfc7905(Crypt::AuthEnc::ChaCha20Poly1305 self, SV * nonce, UV seqnum)
    PPCODE:
    {
        int rv;
        STRLEN iv_len=0;
        unsigned char *iv=NULL;

        if (!SvPOK_spec(nonce)) croak("FATAL: nonce must be string/buffer scalar");
        iv = (unsigned char *) SvPVbyte(nonce, iv_len);
        if (self->finalized) croak("FATAL: AEAD object already finalized");
        rv = chacha20poly1305_setiv_rfc7905(&self->state, iv, (unsigned long)iv_len, (ulong64)seqnum);
        if (rv != CRYPT_OK) croak("FATAL: chacha20poly1305_setiv_rfc7905 failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

void
adata_add(Crypt::AuthEnc::ChaCha20Poly1305 self, SV * data)
    PPCODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data;

        if (self->finalized) croak("FATAL: AEAD object already finalized");
        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        rv = chacha20poly1305_add_aad(&self->state, in_data, (unsigned long)in_data_len);
        if (rv != CRYPT_OK) croak("FATAL: chacha20poly1305_add_aad failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

SV *
decrypt_add(Crypt::AuthEnc::ChaCha20Poly1305 self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data, *out_data;

        if (self->finalized) croak("FATAL: AEAD object already finalized");
        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        if (in_data_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          RETVAL = NEWSV(0, in_data_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, in_data_len);
          out_data = (unsigned char *)SvPVX(RETVAL);
          rv = chacha20poly1305_decrypt(&self->state, in_data, (unsigned long)in_data_len, out_data);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: chacha20poly1305_decrypt failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL

SV *
encrypt_add(Crypt::AuthEnc::ChaCha20Poly1305 self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data, *out_data;

        if (self->finalized) croak("FATAL: AEAD object already finalized");
        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        if (in_data_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          RETVAL = NEWSV(0, in_data_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, in_data_len);
          out_data = (unsigned char *)SvPVX(RETVAL);
          rv = chacha20poly1305_encrypt(&self->state, in_data, (unsigned long)in_data_len, out_data);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: chacha20poly1305_encrypt failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL

void
encrypt_done(Crypt::AuthEnc::ChaCha20Poly1305 self)
    PPCODE:
    {
        int rv;
        unsigned char tag[MAXBLOCKSIZE];
        unsigned long tag_len = sizeof(tag);

        if (self->finalized) croak("FATAL: AEAD object already finalized");
        rv = chacha20poly1305_done(&self->state, tag, &tag_len);
        if (rv != CRYPT_OK) croak("FATAL: chacha20poly1305_done failed: %s", error_to_string(rv));
        self->finalized = 1;
        XPUSHs(sv_2mortal(newSVpvn((char*)tag, tag_len)));
        zeromem(tag, sizeof(tag));
    }

void
decrypt_done(Crypt::AuthEnc::ChaCha20Poly1305 self, ...)
    PPCODE:
    {
        int rv;
        unsigned char tag[MAXBLOCKSIZE];
        unsigned long tag_len = sizeof(tag);
        STRLEN expected_tag_len;
        unsigned char *expected_tag;

        if (self->finalized) croak("FATAL: AEAD object already finalized");
        rv = chacha20poly1305_done(&self->state, tag, &tag_len);
        if (rv != CRYPT_OK) croak("FATAL: chacha20poly1305_done failed: %s", error_to_string(rv));
        self->finalized = 1;
        if (items == 1) {
          XPUSHs(sv_2mortal(newSVpvn((char*)tag, tag_len)));
            zeromem(tag, sizeof(tag));
    }
        else {
          if (!SvPOK_spec(ST(1))) croak("FATAL: expected_tag must be string/buffer scalar");
          expected_tag = (unsigned char *) SvPVbyte(ST(1), expected_tag_len);
          if (expected_tag_len!=tag_len) {
            XPUSHs(sv_2mortal(newSViv(0))); /* false */
          }
          else if (mem_neq(expected_tag, tag, tag_len)) {
            XPUSHs(sv_2mortal(newSViv(0))); /* false */
          }
          else {
            XPUSHs(sv_2mortal(newSViv(1))); /* true */
          }
        }
    }

void
chacha20poly1305_encrypt_authenticate(SV *key, SV *nonce, SV *header, SV *plaintext)
    PPCODE:
    {
        STRLEN k_len = 0, n_len = 0, h_len = 0, pt_len = 0;
        unsigned char *k = NULL, *n = NULL, *h = NULL, *pt = NULL;
        int rv;
        unsigned char tag[MAXBLOCKSIZE];
        unsigned long tag_len = sizeof(tag);
        SV *output;

        if (!SvPOK_spec(key)) croak("FATAL: key must be string/buffer scalar");
        k  = (unsigned char *) SvPVbyte(key, k_len);
        if (!SvPOK_spec(nonce)) croak("FATAL: nonce must be string/buffer scalar");
        n  = (unsigned char *) SvPVbyte(nonce, n_len);
        if (!SvPOK_spec(plaintext)) croak("FATAL: plaintext must be string/buffer scalar");
        pt = (unsigned char *) SvPVbyte(plaintext, pt_len);
        if (header && SvOK(header)) {
          if (!SvPOK_spec(header)) croak("FATAL: header must be string/buffer scalar");
          h = (unsigned char *) SvPVbyte(header, h_len);
            zeromem(tag, sizeof(tag));
    }

        output = NEWSV(0, pt_len > 0 ? pt_len : 1); /* avoid zero! */
        SvPOK_only(output);
        SvCUR_set(output, pt_len);

        rv = chacha20poly1305_memory(k, (unsigned long)k_len, n, (unsigned long)n_len, h, (unsigned long)h_len,
                                     pt, (unsigned long)pt_len, (unsigned char *)SvPVX(output), tag, &tag_len,
                                     CHACHA20POLY1305_ENCRYPT);

        if (rv != CRYPT_OK) {
          SvREFCNT_dec(output);
          croak("FATAL: chacha20poly1305_memory failed: %s", error_to_string(rv));
        }
        XPUSHs(sv_2mortal(output));
        XPUSHs(sv_2mortal(newSVpvn((char*)tag, tag_len)));
    }

void
chacha20poly1305_decrypt_verify(SV *key, SV *nonce, SV *header, SV *ciphertext, SV *tagsv)
    PPCODE:
    {
        STRLEN k_len = 0, n_len = 0, h_len = 0, ct_len = 0, t_len = 0;
        unsigned char *k = NULL, *n = NULL, *h = NULL, *ct = NULL, *t = NULL;
        int rv;
        unsigned char tag[MAXBLOCKSIZE];
        unsigned long tag_len;
        SV *output;

        if (!SvPOK_spec(key)) croak("FATAL: key must be string/buffer scalar");
        k  = (unsigned char *) SvPVbyte(key, k_len);
        if (!SvPOK_spec(nonce)) croak("FATAL: nonce must be string/buffer scalar");
        n  = (unsigned char *) SvPVbyte(nonce, n_len);
        if (!SvPOK_spec(ciphertext)) croak("FATAL: ciphertext must be string/buffer scalar");
        ct = (unsigned char *) SvPVbyte(ciphertext, ct_len);
        if (!SvPOK_spec(tagsv)) croak("FATAL: tag must be string/buffer scalar");
        t  = (unsigned char *) SvPVbyte(tagsv, t_len);
        if (header && SvOK(header)) {
          if (!SvPOK_spec(header)) croak("FATAL: header must be string/buffer scalar");
          h = (unsigned char *) SvPVbyte(header, h_len);
            zeromem(tag, sizeof(tag));
    }

        output = NEWSV(0, ct_len > 0 ? ct_len : 1); /* avoid zero! */
        SvPOK_only(output);
        SvCUR_set(output, ct_len);
        /* Clamp malformed tags to the stack buffer size before copying. */
        tag_len = (unsigned long)(t_len > sizeof(tag) ? sizeof(tag) : t_len);
        if (tag_len > 0) {
          Copy(t, tag, tag_len, unsigned char);
        }

        rv = chacha20poly1305_memory(k, (unsigned long)k_len, n, (unsigned long)n_len, h, (unsigned long)h_len,
                                     ct, (unsigned long)ct_len, (unsigned char *)SvPVX(output), tag, &tag_len,
                                     CHACHA20POLY1305_DECRYPT);

        if (rv != CRYPT_OK) {
          SvREFCNT_dec(output);
          XPUSHs(sv_2mortal(newSVpvn(NULL,0))); /* undef */
        }
        else {
          XPUSHs(sv_2mortal(output));
        }
    }
