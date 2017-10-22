MODULE = CryptX         PACKAGE = Crypt::Stream::ChaCha

Crypt::Stream::ChaCha
_new(SV * key, SV * nonce, UV counter = 0, int rounds = 20)
    CODE:
    {
        int rv;
        STRLEN iv_len=0, k_len=0;
        unsigned char *iv=NULL, *k=NULL;

        if (!SvPOK(key))   croak("FATAL: key must be string/buffer scalar");
        if (!SvPOK(nonce)) croak("FATAL: nonce must be string/buffer scalar");
        k  = (unsigned char *) SvPVbyte(key, k_len);
        iv = (unsigned char *) SvPVbyte(nonce, iv_len);

        Newz(0, RETVAL, 1, struct chacha_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = chacha_setup(&RETVAL->state, k, (unsigned long)k_len, rounds);
        if (rv != CRYPT_OK) croak("FATAL: chacha_setup failed: %s", error_to_string(rv));

        if (iv_len == 12) {
          rv = chacha_ivctr32(&RETVAL->state, iv, (unsigned long)iv_len, (ulong32)counter);
          if (rv != CRYPT_OK) croak("FATAL: chacha_ivctr32 failed: %s", error_to_string(rv));
        }
        else if (iv_len == 8) {
          rv = chacha_ivctr64(&RETVAL->state, iv, (unsigned long)iv_len, (ulong64)counter);
          if (rv != CRYPT_OK) croak("FATAL: chacha_ivctr64 failed: %s", error_to_string(rv));
        }
        else {
          croak("FATAL: chacha IV length must be 8 or 12 bytes");
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Stream::ChaCha self)
    CODE:
        chacha_done(&self->state);
        Safefree(self);

Crypt::Stream::ChaCha
clone(Crypt::Stream::ChaCha self)
    CODE:
        Newz(0, RETVAL, 1, struct chacha_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(&self->state, &RETVAL->state, 1, struct chacha_struct);
    OUTPUT:
        RETVAL

SV *
keystream(Crypt::Stream::ChaCha self, STRLEN out_len)
    CODE:
    {
        int rv;
        unsigned char *out_data;

        RETVAL = NEWSV(0, out_len);
        SvPOK_only(RETVAL);
        SvCUR_set(RETVAL, out_len);
        out_data = (unsigned char *)SvPVX(RETVAL);
        rv = chacha_keystream(&self->state, out_data, out_len);
        if (rv != CRYPT_OK) {
          SvREFCNT_dec(RETVAL);
          croak("FATAL: chacha_keystream failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

SV *
crypt(Crypt::Stream::ChaCha self, SV * data)
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
          out_data = (unsigned char *)SvPVX(RETVAL);
          rv = chacha_crypt(&self->state, in_data, (unsigned long)in_data_len, out_data);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: chacha_crypt failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL
