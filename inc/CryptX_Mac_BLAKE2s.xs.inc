MODULE = CryptX         PACKAGE = Crypt::Mac::BLAKE2s

PROTOTYPES: DISABLE

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

Crypt::Mac::BLAKE2s
new(Class, unsigned long size, SV * key)
    CODE:
    {
        STRLEN k_len=0;
        unsigned char *k=NULL;
        int rv;

        if (!SvPOK(key)) croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);

        Newz(0, RETVAL, 1, blake2smac_state);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = blake2smac_init(RETVAL, size, k, (unsigned long)k_len);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: blake2s_init failed: %s", error_to_string(rv));
        }
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
        Newz(0, RETVAL, 1, blake2smac_state);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(self, RETVAL, 1, blake2smac_state);
    OUTPUT:
        RETVAL

void
add(Crypt::Mac::BLAKE2s self, ...)
    PPCODE:
    {
        int rv, i;
        STRLEN in_data_len;
        unsigned char *in_data;

        for(i = 1; i < items; i++) {
          in_data = (unsigned char *)SvPVbyte(ST(i), in_data_len);
          if (in_data_len > 0) {
            rv = blake2smac_process(self, in_data, (unsigned long)in_data_len);
            if (rv != CRYPT_OK) croak("FATAL: blake2s_process failed: %s", error_to_string(rv));
          }
        }
        XPUSHs(ST(0)); /* return self */
    }

SV *
mac(Crypt::Mac::BLAKE2s self)
    ALIAS:
        hexmac  = 1
        b64mac  = 2
        b64umac = 3
    CODE:
    {
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long maclen, outlen;
        int rv;
        char out[MAXBLOCKSIZE*2+1];

        maclen = sizeof(mac);
        rv = blake2smac_done(self, mac, &maclen);
        if (rv != CRYPT_OK) croak("FATAL: blake2smac_done failed: %s", error_to_string(rv));
        outlen = sizeof(out);
        if (ix == 3) {
          rv = base64url_encode(mac, maclen, out, &outlen);
          if (rv != CRYPT_OK) croak("FATAL: base64url_encode failed: %s", error_to_string(rv));
          RETVAL = newSVpvn(out, outlen);
        }
        if (ix == 2) {
          rv = base64_encode(mac, maclen, out, &outlen);
          if (rv != CRYPT_OK) croak("FATAL: base64_encode failed: %s", error_to_string(rv));
          RETVAL = newSVpvn(out, outlen);
        }
        if (ix == 1) {
          rv = base16_encode(mac, maclen, out, &outlen, 0);
          if (rv != CRYPT_OK) croak("FATAL: base16_encode failed: %s", error_to_string(rv));
          RETVAL = newSVpvn(out, outlen);
        }
        else {
          RETVAL = newSVpvn((char * )mac, maclen);
        }
    }
    OUTPUT:
        RETVAL

SV *
blake2s(unsigned long size, SV * key, ...)
    ALIAS:
        blake2s_hex  = 1
        blake2s_b64  = 2
        blake2s_b64u = 3
    CODE:
    {
        STRLEN inlen, klen;
        unsigned char *in;
        unsigned char *k = (unsigned char *)SvPVbyte(key, klen);
        int rv, i;
        unsigned char mac[MAXBLOCKSIZE];
        unsigned long len = sizeof(mac), outlen;
        char out[MAXBLOCKSIZE*2];
        blake2smac_state st;

        if (size < len) len = size;
        rv = blake2smac_init(&st, len, k, (unsigned long)klen);
        if (rv != CRYPT_OK) croak("FATAL: blake2smac_init failed: %s", error_to_string(rv));
        for (i = 2; i < items; i++) {
          in = (unsigned char *)SvPVbyte(ST(i), inlen);
          if (inlen > 0) {
            rv = blake2smac_process(&st, in, (unsigned long)inlen);
            if (rv != CRYPT_OK) croak("FATAL: blake2smac_process failed: %s", error_to_string(rv));
          }
        }
        rv = blake2smac_done(&st, mac, &len);
        if (rv != CRYPT_OK) croak("FATAL: blake2smac_done failed: %s", error_to_string(rv));

        outlen = sizeof(out);
        if (ix == 3) {
          rv = base64url_encode(mac, len, out, &outlen);
          if (rv != CRYPT_OK) croak("FATAL: base64url_encode failed: %s", error_to_string(rv));
          RETVAL = newSVpvn((char *) out, outlen);
        }
        else if (ix == 2) {
          rv = base64_encode(mac, len, out, &outlen);
          if (rv != CRYPT_OK) croak("FATAL: base64_encode failed: %s", error_to_string(rv));
          RETVAL = newSVpvn(out, outlen);
        }
        else if (ix == 1) {
          rv = base16_encode(mac, len, out, &outlen, 0);
          if (rv != CRYPT_OK) croak("FATAL: base16_encode failed: %s", error_to_string(rv));
          RETVAL = newSVpvn(out, outlen);
        }
        else {
          RETVAL = newSVpvn((char *) mac, len);
        }
    }
    OUTPUT:
        RETVAL
