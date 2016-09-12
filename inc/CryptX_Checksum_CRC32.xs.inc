MODULE = CryptX         PACKAGE = Crypt::Checksum::CRC32

Crypt::Checksum::CRC32
new(Class)
    CODE:
        Newz(0, RETVAL, 1, crc32_state);
        if (!RETVAL) croak("FATAL: Newz failed");
        crc32_init(RETVAL);
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Checksum::CRC32 self)
    CODE:
        Safefree(self);

void
reset(Crypt::Checksum::CRC32 self)
    CODE:
        crc32_init(self);

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
          if (inlen>0) crc32_update(self, in, (unsigned long)inlen);
        }
        XPUSHs(ST(0)); /* return self */
    }

SV *
digest(Crypt::Checksum::CRC32 self)
    CODE:
    {
        unsigned char hash[4];
        crc32_finish(self, hash, 4);
        RETVAL = newSVpvn((char *) hash, 4);
    }
    OUTPUT:
        RETVAL

SV *
hexdigest(Crypt::Checksum::CRC32 self)
    CODE:
    {
        unsigned long i;
        unsigned char hash[4];
        char hash_hex[4*2 + 1];
        crc32_finish(self, hash, 4);
        hash_hex[0] = '\0';
        for(i=0; i<4; i++) sprintf(&hash_hex[2*i], "%02x", hash[i]);
        RETVAL = newSVpvn(hash_hex, strlen(hash_hex));
    }
    OUTPUT:
        RETVAL

