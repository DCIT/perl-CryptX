MODULE = CryptX         PACKAGE = Crypt::Mac::Pelican

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

Crypt::Mac::Pelican
_new(SV * key)
    CODE:
    {
        STRLEN k_len=0;
        unsigned char *k=NULL;
        int rv;        

        if (!SvPOK(key)) croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);

        Newz(0, RETVAL, 1, struct pelican_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = pelican_init(&RETVAL->state, k, k_len);        
        if (rv != CRYPT_OK) croak("FATAL: pelican_init failed: %s", error_to_string(rv));
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
        if (in_data_len>=0) {
          rv = pelican_process(&self->state, in_data, in_data_len);
          if (rv != CRYPT_OK) croak("FATAL: pelican_process failed: %s", error_to_string(rv));
        }
    }

SV *
mac(Crypt::Mac::Pelican self)
    CODE:
    {
        char mac[MAXBLOCKSIZE];
        unsigned long mac_len;
        int rv;

        mac_len = 16;
        rv = pelican_done(&self->state, (unsigned char*)mac);
        if (rv != CRYPT_OK) croak("FATAL: pelican_done failed: %s", error_to_string(rv));
        RETVAL = newSVpvn(mac, mac_len);
    }
    OUTPUT:
        RETVAL

SV *
b64mac(Crypt::Mac::Pelican self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long mac_len;
        int rv;
        unsigned long outlen;
        char mac_base64[MAXBLOCKSIZE*2 + 1];

        mac_len = 16;
        rv = pelican_done(&self->state, mac);
        if (rv != CRYPT_OK) croak("FATAL: pelican_done failed: %s", error_to_string(rv));
        outlen = sizeof(mac_base64);
        rv = base64_encode(mac, mac_len, (unsigned char*)mac_base64, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base64_encode failed: %s", error_to_string(rv));         
        RETVAL = newSVpvn(mac_base64, outlen);
    }
    OUTPUT:
        RETVAL

SV *
hexmac(Crypt::Mac::Pelican self)
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long mac_len;
        int rv, i;
        char mac_hex[MAXBLOCKSIZE*2 + 1];

        mac_len = 16;
        rv = pelican_done(&self->state, mac);
        if (rv != CRYPT_OK) croak("FATAL: pelican_done failed: %s", error_to_string(rv));
        mac_hex[0] = '\0';
        for(i=0; i<mac_len; i++)
            sprintf(&mac_hex[2*i], "%02x", mac[i]);
        RETVAL = newSVpvn(mac_hex, strlen(mac_hex));
    }
    OUTPUT:
        RETVAL
