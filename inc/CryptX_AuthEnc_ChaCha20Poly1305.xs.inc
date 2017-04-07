MODULE = CryptX       PACKAGE = Crypt::AuthEnc::ChaCha20Poly1305

Crypt::AuthEnc::ChaCha20Poly1305
_new(SV * key, SV * nonce)
    CODE:
    {
        int rv;
        STRLEN iv_len=0, k_len=0;
        unsigned char *iv=NULL, *k=NULL;

        if (!SvPOK(key))   croak("FATAL: key must be string/buffer scalar");
        if (!SvPOK(nonce)) croak("FATAL: nonce must be string/buffer scalar");
        k  = (unsigned char *) SvPVbyte(key, k_len);
        iv = (unsigned char *) SvPVbyte(nonce, iv_len);

        Newz(0, RETVAL, 1, struct chacha20poly1305_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = chacha20poly1305_init(&RETVAL->state, k, (unsigned long)k_len);
        if (rv != CRYPT_OK) croak("FATAL: chacha20poly1305_init failed: %s", error_to_string(rv));

        rv = chacha20poly1305_setiv(&RETVAL->state, iv, (unsigned long)iv_len);
        if (rv != CRYPT_OK) croak("FATAL: chacha20poly1305_setiv failed: %s", error_to_string(rv));
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::AuthEnc::ChaCha20Poly1305 self)
    CODE:
        Safefree(self);

Crypt::AuthEnc::ChaCha20Poly1305
clone(Crypt::AuthEnc::ChaCha20Poly1305 self)
    CODE:
        Newz(0, RETVAL, 1, struct chacha20poly1305_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(&self->state, &RETVAL->state, 1, struct chacha20poly1305_struct);
    OUTPUT:
        RETVAL

int
adata_add(Crypt::AuthEnc::ChaCha20Poly1305 self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        rv = chacha20poly1305_add_aad(&self->state, in_data, (unsigned long)in_data_len);
        if (rv != CRYPT_OK) croak("FATAL: chacha20poly1305_add_aad failed: %s", error_to_string(rv));
        RETVAL = rv;
    }
    OUTPUT:
        RETVAL

SV *
decrypt_add(Crypt::AuthEnc::ChaCha20Poly1305 self, SV * data)
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
          rv = chacha20poly1305_decrypt(&self->state, in_data, (unsigned long)in_data_len, out_data);
          if (rv != CRYPT_OK) croak("FATAL: chacha20poly1305_decrypt failed: %s", error_to_string(rv));
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

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        if (in_data_len==0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          RETVAL = NEWSV(0, in_data_len);
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, in_data_len);
          out_data = (unsigned char *)SvPV_nolen(RETVAL);
          rv = chacha20poly1305_encrypt(&self->state, in_data, (unsigned long)in_data_len, out_data);
          if (rv != CRYPT_OK) croak("FATAL: chacha20poly1305_encrypt failed: %s", error_to_string(rv));
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

        rv = chacha20poly1305_done(&self->state, tag, &tag_len);
        if (rv != CRYPT_OK) croak("FATAL: chacha20poly1305_done failed: %s", error_to_string(rv));
        XPUSHs(sv_2mortal(newSVpvn((char*)tag, tag_len)));
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

        rv = chacha20poly1305_done(&self->state, tag, &tag_len);
        if (rv != CRYPT_OK) croak("FATAL: chacha20poly1305_done failed: %s", error_to_string(rv));
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
