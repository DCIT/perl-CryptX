MODULE = CryptX         PACKAGE = Crypt::Stream::Sosemanuk

PROTOTYPES: DISABLE

Crypt::Stream::Sosemanuk
new(Class, SV * key, SV * nonce=&PL_sv_undef)
    CODE:
    {
        int rv;
        STRLEN iv_len=0, k_len=0;
        unsigned char *iv=NULL, *k=NULL;

        if (!SvPOK(key))   croak("FATAL: key must be string/buffer scalar");
        k  = (unsigned char *)SvPVbyte(key, k_len);

        Newz(0, RETVAL, 1, sosemanuk_state);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = sosemanuk_setup(RETVAL, k, (unsigned long)k_len);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: sosemanuk_setup failed: %s", error_to_string(rv));
        }

        if (SvOK(nonce)) {
          if (!SvPOK(nonce)) croak("FATAL: nonce must be string/buffer scalar");
          iv = (unsigned char *)SvPVbyte(nonce, iv_len);
          rv = sosemanuk_setiv(RETVAL, iv, (unsigned long)iv_len);
        }
        else {
          rv = sosemanuk_setiv(RETVAL, NULL, 0);
        }
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: sosemanuk_setiv failed: %s", error_to_string(rv));
        }

    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Stream::Sosemanuk self)
    CODE:
        sosemanuk_done(self);
        Safefree(self);

Crypt::Stream::Sosemanuk
clone(Crypt::Stream::Sosemanuk self)
    CODE:
        Newz(0, RETVAL, 1, sosemanuk_state);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(self, RETVAL, 1, sosemanuk_state);
    OUTPUT:
        RETVAL

SV *
keystream(Crypt::Stream::Sosemanuk self, STRLEN out_len)
    CODE:
    {
        int rv;
        unsigned char *out_data;

        if (out_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          RETVAL = NEWSV(0, out_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, out_len);
          out_data = (unsigned char *)SvPVX(RETVAL);
          rv = sosemanuk_keystream(self, out_data, (unsigned long)out_len);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: sosemanuk_keystream failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL

SV *
crypt(Crypt::Stream::Sosemanuk self, SV * data)
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
          rv = sosemanuk_crypt(self, in_data, (unsigned long)in_data_len, out_data);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: sosemanuk_crypt failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL
