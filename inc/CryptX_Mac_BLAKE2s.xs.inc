MODULE = CryptX         PACKAGE = Crypt::Mac::BLAKE2s

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

Crypt::Mac::BLAKE2s
_new(int size, SV * key)
    CODE:
    {
        STRLEN k_len=0;
        unsigned char *k=NULL;
        int rv;

        if (!SvPOK(key)) croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);

        Newz(0, RETVAL, 1, struct blake2s_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = blake2smac_init(&RETVAL->state, size, k, (unsigned long)k_len);
        if (rv != CRYPT_OK) croak("FATAL: blake2s_init failed: %s", error_to_string(rv));
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Mac::BLAKE2s self)
    CODE:
        Safefree(self);

Crypt::Mac::BLAKE2s
clone(Crypt::Mac::BLAKE2s self)
    CODE:
        Newz(0, RETVAL, 1, struct blake2s_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(&self->state, &RETVAL->state, 1, struct blake2s_struct);
    OUTPUT:
        RETVAL

void
_add_single(Crypt::Mac::BLAKE2s self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        if (in_data_len>0) {
          rv = blake2smac_process(&self->state, in_data, (unsigned long)in_data_len);
          if (rv != CRYPT_OK) croak("FATAL: blake2s_process failed: %s", error_to_string(rv));
        }
    }

SV *
mac(Crypt::Mac::BLAKE2s self)
    CODE:
    {
        char mac[MAXBLOCKSIZE];
        unsigned long mac_len;
        int rv;

        mac_len = sizeof(mac);
        rv = blake2smac_done(&self->state, (unsigned char*)mac, &mac_len);
        if (rv != CRYPT_OK) croak("FATAL: blake2smac_done failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(mac, mac_len);
    }
    OUTPUT:
        RETVAL

SV *
b64mac(Crypt::Mac::BLAKE2s self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long mac_len;
        int rv;
        unsigned long outlen;
        char mac_base64[MAXBLOCKSIZE*2 + 1];

        mac_len = sizeof(mac);
        rv = blake2smac_done(&self->state, mac, &mac_len);
        if (rv != CRYPT_OK) croak("FATAL: blake2smac_done failed: %s", error_to_string(rv));
        outlen = sizeof(mac_base64);
        rv = base64_encode(mac, mac_len, (unsigned char*)mac_base64, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base64_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(mac_base64, outlen);
    }
    OUTPUT:
        RETVAL

SV *
b64umac(Crypt::Mac::BLAKE2s self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long mac_len;
        int rv;
        unsigned long outlen;
        char mac_base64[MAXBLOCKSIZE*2 + 1];

        mac_len = sizeof(mac);
        rv = blake2smac_done(&self->state, mac, &mac_len);
        if (rv != CRYPT_OK) croak("FATAL: blake2smac_done failed: %s", error_to_string(rv));
        outlen = sizeof(mac_base64);
        rv = base64url_encode(mac, mac_len, (unsigned char*)mac_base64, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base64url_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(mac_base64, outlen);
    }
    OUTPUT:
        RETVAL

SV *
hexmac(Crypt::Mac::BLAKE2s self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long mac_len, i;
        int rv;
        char mac_hex[MAXBLOCKSIZE*2 + 1];

        mac_len = sizeof(mac);
        rv = blake2smac_done(&self->state, mac, &mac_len);
        if (rv != CRYPT_OK) croak("FATAL: blake2smac_done failed: %s", error_to_string(rv));
        mac_hex[0] = '\0';
        for(i=0; i<mac_len; i++)
            sprintf(&mac_hex[2*i], "%02x", mac[i]);
        RETVAL = newSVpvn(mac_hex, strlen(mac_hex));
    }
    OUTPUT:
        RETVAL
