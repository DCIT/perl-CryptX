MODULE = CryptX         PACKAGE = Crypt::Checksum::Adler32

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
    CODE:
    {
        unsigned char hash[4];
        adler32_finish(self, hash, 4); /* returns void */
        RETVAL = newSVpvn((char *) hash, 4);
    }
    OUTPUT:
        RETVAL

SV *
hexdigest(Crypt::Checksum::Adler32 self)
    CODE:
    {
        unsigned long i;
        unsigned char hash[4];
        char hash_hex[4*2 + 1];
        adler32_finish(self, hash, 4); /* returns void */
        hash_hex[0] = '\0';
        for(i=0; i<4; i++) sprintf(&hash_hex[2*i], "%02x", hash[i]);
        RETVAL = newSVpvn(hash_hex, strlen(hash_hex));
    }
    OUTPUT:
        RETVAL

