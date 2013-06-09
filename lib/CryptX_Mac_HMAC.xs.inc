MODULE = CryptX         PACKAGE = Crypt::Mac::HMAC

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

Crypt::Mac::HMAC
_new(char * hash_name, SV * key)
    CODE:
    {
        STRLEN k_len=0;
        unsigned char *k=NULL;
        int rv;        
        int id;

        id = find_hash(hash_name);
        if(id==-1) croak("FATAL: find_hash failed for '%s'", hash_name);

        if (!SvPOK(key)) croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);

        Newz(0, RETVAL, 1, struct hmac_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = hmac_init(&RETVAL->state, id, k, (unsigned long)k_len);
        if (rv != CRYPT_OK) croak("FATAL: hmac_init failed: %s", error_to_string(rv));
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Mac::HMAC self)
    CODE:
        Safefree(self);

Crypt::Mac::HMAC
clone(Crypt::Mac::HMAC self)
    CODE:
        Newz(0, RETVAL, 1, struct hmac_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(&self->state, &RETVAL->state, 1, struct hmac_struct);
    OUTPUT:
        RETVAL

void
_add_single(Crypt::Mac::HMAC self, SV * data)
    CODE:
    {
        int rv;
        STRLEN in_data_len;
        unsigned char *in_data;

        in_data = (unsigned char *)SvPVbyte(data, in_data_len);        
        if (in_data_len>0) {
          rv = hmac_process(&self->state, in_data, (unsigned long)in_data_len);
          if (rv != CRYPT_OK) croak("FATAL: hmac_process failed: %s", error_to_string(rv));
        }
    }

SV *
mac(Crypt::Mac::HMAC self)
    CODE:
    {
        char mac[MAXBLOCKSIZE];
        unsigned long mac_len;
        int rv;

        mac_len = sizeof(mac);
        rv = hmac_done(&self->state, (unsigned char*)mac, &mac_len);
        if (rv != CRYPT_OK) croak("FATAL: hmac_done failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(mac, mac_len);
    }
    OUTPUT:
        RETVAL

SV *
b64mac(Crypt::Mac::HMAC self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long mac_len;
        int rv;
        unsigned long outlen;
        char mac_base64[MAXBLOCKSIZE*2 + 1];

        mac_len = sizeof(mac);
        rv = hmac_done(&self->state, mac, &mac_len);
        if (rv != CRYPT_OK) croak("FATAL: hmac_done failed: %s", error_to_string(rv));
        outlen = sizeof(mac_base64);
        rv = base64_encode(mac, mac_len, (unsigned char*)mac_base64, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base64_encode failed: %s", error_to_string(rv));         
        RETVAL = newSVpvn(mac_base64, outlen);
    }
    OUTPUT:
        RETVAL

SV *
hexmac(Crypt::Mac::HMAC self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long mac_len, i;
        int rv;
        char mac_hex[MAXBLOCKSIZE*2 + 1];

        mac_len = sizeof(mac);
        rv = hmac_done(&self->state, mac, &mac_len);
        if (rv != CRYPT_OK) croak("FATAL: hmac_done failed: %s", error_to_string(rv));
        mac_hex[0] = '\0';
        for(i=0; i<mac_len; i++)
            sprintf(&mac_hex[2*i], "%02x", mac[i]);
        RETVAL = newSVpvn(mac_hex, strlen(mac_hex));
    }
    OUTPUT:
        RETVAL
