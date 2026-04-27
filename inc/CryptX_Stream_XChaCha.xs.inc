MODULE = CryptX         PACKAGE = Crypt::Stream::XChaCha

PROTOTYPES: DISABLE

Crypt::Stream::XChaCha
new(Class, SV * key, SV * nonce, int rounds = 20)
    CODE:
    {
        int rv;
        STRLEN iv_len=0, k_len=0;
        unsigned char *iv=NULL, *k=NULL;

        if (!SvPOK_spec(key))   croak("FATAL: key must be string/buffer scalar");
        if (!SvPOK_spec(nonce)) croak("FATAL: nonce must be string/buffer scalar");
        k  = (unsigned char *)SvPVbyte(key, k_len);
        iv = (unsigned char *)SvPVbyte(nonce, iv_len);

        Newz(0, RETVAL, 1, chacha_state);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = xchacha20_setup(RETVAL, k, (unsigned long)k_len, iv, (unsigned long)iv_len, rounds);
        if (rv != CRYPT_OK) {
          chacha_done(RETVAL);
          Safefree(RETVAL);
          croak("FATAL: xchacha20_setup failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Stream::XChaCha self)
    CODE:
        chacha_done(self);
        zeromem(self, sizeof(*self));
        Safefree(self);

Crypt::Stream::XChaCha
clone(Crypt::Stream::XChaCha self)
    CODE:
        Newz(0, RETVAL, 1, chacha_state);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(self, RETVAL, 1, chacha_state);
    OUTPUT:
        RETVAL

SV *
keystream(Crypt::Stream::XChaCha self, unsigned long out_len)
    CODE:
    {
        int rv;
        unsigned char *out_data;

        if (out_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          if (out_len == ULONG_MAX) croak("FATAL: output length too large");
          RETVAL = NEWSV(0, out_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, out_len);
          out_data = (unsigned char *)SvPVX(RETVAL);
          rv = chacha_keystream(self, out_data, out_len);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: chacha_keystream failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL

SV *
crypt(Crypt::Stream::XChaCha self, SV * data)
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
          rv = chacha_crypt(self, in_data, (unsigned long)in_data_len, out_data);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: chacha_crypt failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL
