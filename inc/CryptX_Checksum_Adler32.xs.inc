MODULE = CryptX         PACKAGE = Crypt::Checksum::Adler32

PROTOTYPES: DISABLE

Crypt::Checksum::Adler32
new(Class)
    CODE:
    {
        Newz(0, RETVAL, 1, adler32_state);
        if (!RETVAL) croak("FATAL: Newz failed");
        adler32_init(RETVAL); /* returns void */
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Checksum::Adler32 self)
    CODE:
        Safefree(self);

void
reset(Crypt::Checksum::Adler32 self)
    PPCODE:
    {
        adler32_init(self); /* returns void */
        XPUSHs(ST(0)); /* return self */
    }

Crypt::Checksum::Adler32
clone(Crypt::Checksum::Adler32 self)
    CODE:
        Newz(0, RETVAL, 1, adler32_state);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(self, RETVAL, 1, adler32_state);
    OUTPUT:
        RETVAL

void
add(Crypt::Checksum::Adler32 self, ...)
    PPCODE:
    {
        STRLEN inlen;
        int i;
        unsigned char *in;
        for(i=1; i<items; i++) {
          in = (unsigned char *)SvPVbyte(ST(i), inlen);
          if (inlen > 0) {
            adler32_update(self, in, (unsigned long)inlen); /* returns void */
          }
        }
        XPUSHs(ST(0)); /* return self */
    }

SV *
digest(Crypt::Checksum::Adler32 self)
    ALIAS:
        hexdigest = 1
        intdigest = 2
    CODE:
    {
        int rv;
        unsigned char hash[4];
        char out[9];
        unsigned long outlen = 9;
        unsigned int ui32;

        adler32_finish(self, hash, 4); /* returns void */
        if (ix == 1) {
          rv = base16_encode(hash, 4, out, &outlen, 0);
          if (rv != CRYPT_OK) croak("FATAL: base16_encode failed: %s", error_to_string(rv));
          RETVAL = newSVpvn(out, outlen);
        }
        else if (ix == 2) {
          LOAD32H(ui32, hash);
          RETVAL = newSVuv(ui32);
        }
        else {
          RETVAL = newSVpvn((char *) hash, 4);
        }
    }
    OUTPUT:
        RETVAL

SV *
adler32_data(...)
    ALIAS:
        adler32_data_hex = 1
        adler32_data_int = 2
    CODE:
    {
        adler32_state st;
        int rv, j;
        unsigned char hash[4], *in;
        char out[9];
        unsigned long outlen = 9;
        unsigned int ui32;
        STRLEN inlen;

        adler32_init(&st);
        for(j = 0; j < items; j++) {
          in = (unsigned char *)SvPVbyte(ST(j), inlen);
          if (inlen > 0) {
            adler32_update(&st, in, (unsigned long)inlen); /* returns void */
          }
        }
        adler32_finish(&st, hash, 4); /* returns void */
        if (ix == 1) {
          rv = base16_encode(hash, 4, out, &outlen, 0);
          if (rv != CRYPT_OK) croak("FATAL: base16_encode failed: %s", error_to_string(rv));
          RETVAL = newSVpvn(out, outlen);
        }
        else if (ix == 2) {
          LOAD32H(ui32, hash);
          RETVAL = newSVuv(ui32);
        }
        else {
          RETVAL = newSVpvn((char *) hash, 4);
        }
    }
    OUTPUT:
        RETVAL
