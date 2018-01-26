MODULE = CryptX         PACKAGE = Crypt::Mac::Pelican

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

Crypt::Mac::Pelican
new(char * class, SV * key)
    CODE:
    {
        STRLEN k_len=0;
        unsigned char *k=NULL;
        int rv;

        if (!SvPOK(key)) croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);

        Newz(0, RETVAL, 1, struct pelican_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = pelican_init(&RETVAL->state, k, (unsigned long)k_len);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: pelican_init failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Mac::Pelican self)
    CODE:
        Safefree(self);

Crypt::Mac::Pelican
clone(Crypt::Mac::Pelican self)
    CODE:
        Newz(0, RETVAL, 1, struct pelican_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(&self->state, &RETVAL->state, 1, struct pelican_struct);
    OUTPUT:
        RETVAL

void
_add_single(Crypt::Mac::Pelican self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        if (in_data_len>0) {
          rv = pelican_process(&self->state, in_data, (unsigned long)in_data_len);
          if (rv != CRYPT_OK) croak("FATAL: pelican_process failed: %s", error_to_string(rv));
        }
    }

SV *
mac(Crypt::Mac::Pelican self)
    CODE:
    {
        char mac[MAXBLOCKSIZE];
        unsigned long maclen;
        int rv;

        maclen = 16;
        rv = pelican_done(&self->state, (unsigned char*)mac);
        if (rv != CRYPT_OK) croak("FATAL: pelican_done failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(mac, maclen);
    }
    OUTPUT:
        RETVAL

SV *
b64mac(Crypt::Mac::Pelican self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long maclen;
        int rv;
        unsigned long outlen;
        char out[MAXBLOCKSIZE*2];

        maclen = 16;
        rv = pelican_done(&self->state, mac);
        if (rv != CRYPT_OK) croak("FATAL: pelican_done failed: %s", error_to_string(rv));
        outlen = sizeof(out);
        rv = base64_encode(mac, maclen, (unsigned char*)out, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base64_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(out, outlen);
    }
    OUTPUT:
        RETVAL

SV *
b64umac(Crypt::Mac::Pelican self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long maclen;
        int rv;
        unsigned long outlen;
        char out[MAXBLOCKSIZE*2 + 1];

        maclen = 16;
        rv = pelican_done(&self->state, mac);
        if (rv != CRYPT_OK) croak("FATAL: pelican_done failed: %s", error_to_string(rv));
        outlen = sizeof(out);
        rv = base64url_encode(mac, maclen, (unsigned char*)out, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base64url_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(out, outlen);
    }
    OUTPUT:
        RETVAL

SV *
hexmac(Crypt::Mac::Pelican self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long maclen, outlen;
        int rv;
        char out[MAXBLOCKSIZE*2];

        maclen = 16;
        rv = pelican_done(&self->state, mac);
        if (rv != CRYPT_OK) croak("FATAL: pelican_done failed: %s", error_to_string(rv));
        outlen = sizeof(out);
        rv = _base16_encode(mac, maclen, (unsigned char *)out, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base16_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(out, outlen);
    }
    OUTPUT:
        RETVAL

SV *
pelican(SV * key, SV * data)
    CODE:
    {
        STRLEN inlen, klen;
        unsigned char *in = (unsigned char *)SvPVbyte(data, inlen);
        unsigned char *k = (unsigned char *)SvPVbyte(key, klen);
        int rv;
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long len = sizeof(mac);
        len = 16;
        rv = pelican_memory(k, klen, in, inlen, mac);
        if (rv != CRYPT_OK) croak("FATAL: pelican_memory failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char *) mac, len);
    }
    OUTPUT:
        RETVAL

SV *
pelican_hex(SV * key, SV * data)
    CODE:
    {
        STRLEN inlen, klen;
        unsigned char *in = (unsigned char *)SvPVbyte(data, inlen);
        unsigned char *k = (unsigned char *)SvPVbyte(key, klen);
        int rv;
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long len = sizeof(mac), outlen;
        char out[MAXBLOCKSIZE*2];
        len = 16;
        rv = pelican_memory(k, klen, in, inlen, mac);
        if (rv != CRYPT_OK) croak("FATAL: pelican_memory failed: %s", error_to_string(rv));
        outlen = sizeof(out);
        rv = _base16_encode(mac, len, (unsigned char *)out, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base16_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char *) out, outlen);
    }
    OUTPUT:
        RETVAL

SV *
pelican_b64(SV * key, SV * data)
    CODE:
    {
        STRLEN inlen, klen;
        unsigned char *in = (unsigned char *)SvPVbyte(data, inlen);
        unsigned char *k = (unsigned char *)SvPVbyte(key, klen);
        int rv;
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long len = sizeof(mac), outlen;
        char out[MAXBLOCKSIZE*2];
        len = 16;
        rv = pelican_memory(k, klen, in, inlen, mac);
        if (rv != CRYPT_OK) croak("FATAL: pelican_memory failed: %s", error_to_string(rv));
        outlen = sizeof(out);
        rv = base64_encode(mac, len, (unsigned char *)out, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base64_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char *) out, outlen);

    }
    OUTPUT:
        RETVAL

SV *
pelican_b64u(SV * key, SV * data)
    CODE:
    {
        STRLEN inlen, klen;
        unsigned char *in = (unsigned char *)SvPVbyte(data, inlen);
        unsigned char *k = (unsigned char *)SvPVbyte(key, klen);
        int rv;
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long len = sizeof(mac), outlen;
        char out[MAXBLOCKSIZE*2];
        len = 16;
        rv = pelican_memory(k, klen, in, inlen, mac);
        if (rv != CRYPT_OK) croak("FATAL: pelican_memory failed: %s", error_to_string(rv));
        outlen = sizeof(out);
        rv = base64url_encode(mac, len, (unsigned char *)out, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base64url_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn((char *) out, outlen);
    }
    OUTPUT:
        RETVAL
