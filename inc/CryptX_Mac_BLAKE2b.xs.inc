MODULE = CryptX         PACKAGE = Crypt::Mac::BLAKE2b

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

Crypt::Mac::BLAKE2b
new(char * class, int size, SV * key)
    CODE:
    {
        STRLEN k_len=0;
        unsigned char *k=NULL;
        int rv;

        if (!SvPOK(key)) croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);

        Newz(0, RETVAL, 1, struct blake2b_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = blake2bmac_init(&RETVAL->state, size, k, (unsigned long)k_len);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: blake2b_init failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Mac::BLAKE2b self)
    CODE:
        Safefree(self);

Crypt::Mac::BLAKE2b
clone(Crypt::Mac::BLAKE2b self)
    CODE:
        Newz(0, RETVAL, 1, struct blake2b_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(&self->state, &RETVAL->state, 1, struct blake2b_struct);
    OUTPUT:
        RETVAL

void
_add_single(Crypt::Mac::BLAKE2b self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        if (in_data_len>0) {
          rv = blake2bmac_process(&self->state, in_data, (unsigned long)in_data_len);
          if (rv != CRYPT_OK) croak("FATAL: blake2b_process failed: %s", error_to_string(rv));
        }
    }

SV *
mac(Crypt::Mac::BLAKE2b self)
    CODE:
    {
        char mac[MAXBLOCKSIZE];
        unsigned long maclen;
        int rv;

        maclen = sizeof(mac);
        rv = blake2bmac_done(&self->state, (unsigned char*)mac, &maclen);
        if (rv != CRYPT_OK) croak("FATAL: blake2bmac_done failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(mac, maclen);
    }
    OUTPUT:
        RETVAL

SV *
b64mac(Crypt::Mac::BLAKE2b self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long maclen;
        int rv;
        unsigned long outlen;
        char out[MAXBLOCKSIZE*2];

        maclen = sizeof(mac);
        rv = blake2bmac_done(&self->state, mac, &maclen);
        if (rv != CRYPT_OK) croak("FATAL: blake2bmac_done failed: %s", error_to_string(rv));
        outlen = sizeof(out);
        rv = base64_encode(mac, maclen, (unsigned char*)out, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base64_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(out, outlen);
    }
    OUTPUT:
        RETVAL

SV *
b64umac(Crypt::Mac::BLAKE2b self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long maclen;
        int rv;
        unsigned long outlen;
        char out[MAXBLOCKSIZE*2 + 1];

        maclen = sizeof(mac);
        rv = blake2bmac_done(&self->state, mac, &maclen);
        if (rv != CRYPT_OK) croak("FATAL: blake2bmac_done failed: %s", error_to_string(rv));
        outlen = sizeof(out);
        rv = base64url_encode(mac, maclen, (unsigned char*)out, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base64url_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(out, outlen);
    }
    OUTPUT:
        RETVAL

SV *
hexmac(Crypt::Mac::BLAKE2b self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long maclen, outlen;
        int rv;
        char out[MAXBLOCKSIZE*2];

        maclen = sizeof(mac);
        rv = blake2bmac_done(&self->state, mac, &maclen);
        if (rv != CRYPT_OK) croak("FATAL: blake2bmac_done failed: %s", error_to_string(rv));
        outlen = sizeof(out);
        rv = _base16_encode(mac, maclen, (unsigned char *)out, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base16_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(out, outlen);
    }
    OUTPUT:
        RETVAL
