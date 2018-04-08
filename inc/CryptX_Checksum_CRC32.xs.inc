MODULE = CryptX         PACKAGE = Crypt::Checksum::CRC32

PROTOTYPES: DISABLE

Crypt::Checksum::CRC32
new(Class)
    CODE:
    {
        Newz(0, RETVAL, 1, crc32_state);
        if (!RETVAL) croak("FATAL: Newz failed");
        crc32_init(RETVAL); /* returns void */
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Checksum::CRC32 self)
    CODE:
        Safefree(self);

void
reset(Crypt::Checksum::CRC32 self)
    PPCODE:
    {
        crc32_init(self); /* returns void */
        XPUSHs(ST(0)); /* return self */
    }

Crypt::Checksum::CRC32
clone(Crypt::Checksum::CRC32 self)
    CODE:
        Newz(0, RETVAL, 1, crc32_state);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(self, RETVAL, 1, crc32_state);
    OUTPUT:
        RETVAL

void
add(Crypt::Checksum::CRC32 self, ...)
    PPCODE:
    {
        STRLEN inlen;
        int i;
        unsigned char *in;
        for(i=1; i<items; i++) {
          in = (unsigned char *)SvPVbyte(ST(i), inlen);
          if (inlen > 0) {
            crc32_update(self, in, (unsigned long)inlen); /* returns void */
          }
        }
        XPUSHs(ST(0)); /* return self */
    }

SV *
digest(Crypt::Checksum::CRC32 self)
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

        crc32_finish(self, hash, 4); /* returns void */
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
crc32_data(...)
    ALIAS:
        crc32_data_hex = 1
        crc32_data_int = 2
    CODE:
    {
        crc32_state st;
        int rv, j;
        unsigned char hash[4], *in;
        char out[9];
        unsigned long outlen = 9;
        unsigned int ui32;
        STRLEN inlen;

        crc32_init(&st);
        for(j = 0; j < items; j++) {
          in = (unsigned char *)SvPVbyte(ST(j), inlen);
          if (inlen > 0) {
            crc32_update(&st, in, (unsigned long)inlen); /* returns void */
          }
        }
        crc32_finish(&st, hash, 4); /* returns void */
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
