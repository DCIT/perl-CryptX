MODULE = CryptX         PACKAGE = Crypt::Mac::OMAC

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

Crypt::Mac::OMAC
_new(char * cipher_name, SV * key)
    CODE:
    {
        STRLEN k_len=0;
        unsigned char *k=NULL;
        int rv;
        int id;

        id = find_cipher(cipher_name);
        if(id==-1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);

        if (!SvPOK(key)) croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);

        Newz(0, RETVAL, 1, struct omac_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = omac_init(&RETVAL->state, id, k, (unsigned long)k_len);
        if (rv != CRYPT_OK) croak("FATAL: omac_init failed: %s", error_to_string(rv));
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Mac::OMAC self)
    CODE:
        Safefree(self);

Crypt::Mac::OMAC
clone(Crypt::Mac::OMAC self)
    CODE:
        Newz(0, RETVAL, 1, struct omac_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(&self->state, &RETVAL->state, 1, struct omac_struct);
    OUTPUT:
        RETVAL

void
_add_single(Crypt::Mac::OMAC self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);
        if (in_data_len>0) {
          rv = omac_process(&self->state, in_data, (unsigned long)in_data_len);
          if (rv != CRYPT_OK) croak("FATAL: omac_process failed: %s", error_to_string(rv));
        }
    }

SV *
mac(Crypt::Mac::OMAC self)
    CODE:
    {
        char mac[MAXBLOCKSIZE];
        unsigned long mac_len;
        int rv;

        mac_len = sizeof(mac);
        rv = omac_done(&self->state, (unsigned char*)mac, &mac_len);
        if (rv != CRYPT_OK) croak("FATAL: omac_done failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(mac, mac_len);
    }
    OUTPUT:
        RETVAL

SV *
b64mac(Crypt::Mac::OMAC self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long mac_len;
        int rv;
        unsigned long outlen;
        char mac_base64[MAXBLOCKSIZE*2 + 1];

        mac_len = sizeof(mac);
        rv = omac_done(&self->state, mac, &mac_len);
        if (rv != CRYPT_OK) croak("FATAL: omac_done failed: %s", error_to_string(rv));
        outlen = sizeof(mac_base64);
        rv = base64_encode(mac, mac_len, (unsigned char*)mac_base64, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base64_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(mac_base64, outlen);
    }
    OUTPUT:
        RETVAL

SV *
b64umac(Crypt::Mac::OMAC self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long mac_len;
        int rv;
        unsigned long outlen;
        char mac_base64[MAXBLOCKSIZE*2 + 1];

        mac_len = sizeof(mac);
        rv = omac_done(&self->state, mac, &mac_len);
        if (rv != CRYPT_OK) croak("FATAL: omac_done failed: %s", error_to_string(rv));
        outlen = sizeof(mac_base64);
        rv = base64url_encode(mac, mac_len, (unsigned char*)mac_base64, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base64url_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(mac_base64, outlen);
    }
    OUTPUT:
        RETVAL

SV *
hexmac(Crypt::Mac::OMAC self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long mac_len, i;
        int rv;
        char mac_hex[MAXBLOCKSIZE*2 + 1];

        mac_len = sizeof(mac);
        rv = omac_done(&self->state, mac, &mac_len);
        if (rv != CRYPT_OK) croak("FATAL: omac_done failed: %s", error_to_string(rv));
        mac_hex[0] = '\0';
        for(i=0; i<mac_len; i++)
            sprintf(&mac_hex[2*i], "%02x", mac[i]);
        RETVAL = newSVpvn(mac_hex, strlen(mac_hex));
    }
    OUTPUT:
        RETVAL
