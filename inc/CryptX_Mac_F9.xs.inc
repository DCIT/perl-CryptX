MODULE = CryptX         PACKAGE = Crypt::Mac::F9

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

Crypt::Mac::F9
new(char * class, char * cipher_name, SV * key)
    CODE:
    {
        STRLEN k_len=0;
        unsigned char *k=NULL;
        int rv;
        int id;

        id = _find_cipher(cipher_name);
        if (id == -1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);

        if (!SvPOK(key)) croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);

        Newz(0, RETVAL, 1, struct f9_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = f9_init(&RETVAL->state, id, k, (unsigned long)k_len);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: f9_init failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Mac::F9 self)
    CODE:
        Safefree(self);

Crypt::Mac::F9
clone(Crypt::Mac::F9 self)
    CODE:
        Newz(0, RETVAL, 1, struct f9_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(&self->state, &RETVAL->state, 1, struct f9_struct);
    OUTPUT:
        RETVAL

void
_add_single(Crypt::Mac::F9 self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        if (in_data_len>0) {
          rv = f9_process(&self->state, in_data, (unsigned long)in_data_len);
          if (rv != CRYPT_OK) croak("FATAL: f9_process failed: %s", error_to_string(rv));
        }
    }

SV *
mac(Crypt::Mac::F9 self)
    CODE:
    {
        char mac[MAXBLOCKSIZE];
        unsigned long maclen;
        int rv;

        maclen = sizeof(mac);
        rv = f9_done(&self->state, (unsigned char*)mac, &maclen);
        if (rv != CRYPT_OK) croak("FATAL: f9_done failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(mac, maclen);
    }
    OUTPUT:
        RETVAL

SV *
b64mac(Crypt::Mac::F9 self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long maclen;
        int rv;
        unsigned long outlen;
        char out[MAXBLOCKSIZE*2];

        maclen = sizeof(mac);
        rv = f9_done(&self->state, mac, &maclen);
        if (rv != CRYPT_OK) croak("FATAL: f9_done failed: %s", error_to_string(rv));
        outlen = sizeof(out);
        rv = base64_encode(mac, maclen, (unsigned char*)out, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base64_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(out, outlen);
    }
    OUTPUT:
        RETVAL

SV *
b64umac(Crypt::Mac::F9 self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long maclen;
        int rv;
        unsigned long outlen;
        char out[MAXBLOCKSIZE*2 + 1];

        maclen = sizeof(mac);
        rv = f9_done(&self->state, mac, &maclen);
        if (rv != CRYPT_OK) croak("FATAL: f9_done failed: %s", error_to_string(rv));
        outlen = sizeof(out);
        rv = base64url_encode(mac, maclen, (unsigned char*)out, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base64url_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(out, outlen);
    }
    OUTPUT:
        RETVAL

SV *
hexmac(Crypt::Mac::F9 self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long maclen, outlen;
        int rv;
        char out[MAXBLOCKSIZE*2];

        maclen = sizeof(mac);
        rv = f9_done(&self->state, mac, &maclen);
        if (rv != CRYPT_OK) croak("FATAL: f9_done failed: %s", error_to_string(rv));
        outlen = sizeof(out);
        rv = _base16_encode(mac, maclen, (unsigned char *)out, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base16_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(out, outlen);
    }
    OUTPUT:
        RETVAL
