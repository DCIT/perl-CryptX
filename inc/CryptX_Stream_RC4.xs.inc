MODULE = CryptX         PACKAGE = Crypt::Stream::RC4

PROTOTYPES: DISABLE

Crypt::Stream::RC4
new(Class, SV * key)
    CODE:
    {
        int rv;
        STRLEN k_len=0;
        unsigned char *k=NULL;

        if (!SvPOK(key))   croak("FATAL: key must be string/buffer scalar");
        k  = (unsigned char *) SvPVbyte(key, k_len);

        Newz(0, RETVAL, 1, rc4_state);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = rc4_stream_setup(RETVAL, k, (unsigned long)k_len);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: rc4_stream_setup failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Stream::RC4 self)
    CODE:
        rc4_stream_done(self);
        Safefree(self);

Crypt::Stream::RC4
clone(Crypt::Stream::RC4 self)
    CODE:
        Newz(0, RETVAL, 1, rc4_state);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(self, RETVAL, 1, rc4_state);
    OUTPUT:
        RETVAL

SV *
keystream(Crypt::Stream::RC4 self, STRLEN out_len)
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
          rv = rc4_stream_keystream(self, out_data, (unsigned long)out_len);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: rc4_stream_keystream failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL

SV *
crypt(Crypt::Stream::RC4 self, SV * data)
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
          rv = rc4_stream_crypt(self, in_data, (unsigned long)in_data_len, out_data);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: rc4_stream_crypt failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL
