MODULE = CryptX         PACKAGE = Crypt::Stream::Salsa20

PROTOTYPES: DISABLE

Crypt::Stream::Salsa20
new(Class, SV * key, SV * nonce, UV counter = 0, int rounds = 20)
    CODE:
    {
        int rv;
        STRLEN iv_len=0, k_len=0;
        unsigned char *iv=NULL, *k=NULL;

        if (!SvPOK(key))   croak("FATAL: key must be string/buffer scalar");
        if (!SvPOK(nonce)) croak("FATAL: nonce must be string/buffer scalar");
        k  = (unsigned char *)SvPVbyte(key, k_len);
        iv = (unsigned char *)SvPVbyte(nonce, iv_len);

        Newz(0, RETVAL, 1, salsa20_state);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = salsa20_setup(RETVAL, k, (unsigned long)k_len, rounds);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: salsa20_setup failed: %s", error_to_string(rv));
        }

        rv = salsa20_ivctr64(RETVAL, iv, (unsigned long)iv_len, (ulong64)counter);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: salsa20_ivctr64 failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Stream::Salsa20 self)
    CODE:
        salsa20_done(self);
        Safefree(self);

Crypt::Stream::Salsa20
clone(Crypt::Stream::Salsa20 self)
    CODE:
        Newz(0, RETVAL, 1, salsa20_state);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(self, RETVAL, 1, salsa20_state);
    OUTPUT:
        RETVAL

SV *
keystream(Crypt::Stream::Salsa20 self, STRLEN out_len)
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
          rv = salsa20_keystream(self, out_data, (unsigned long)out_len);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: salsa20_keystream failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL

SV *
crypt(Crypt::Stream::Salsa20 self, SV * data)
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
          rv = salsa20_crypt(self, in_data, (unsigned long)in_data_len, out_data);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: salsa20_crypt failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL
