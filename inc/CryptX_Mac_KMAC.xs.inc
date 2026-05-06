MODULE = CryptX         PACKAGE = Crypt::Mac::KMAC

PROTOTYPES: DISABLE

#define CRYPTX_MAC_KMAC_MAX_OUTPUT_LEN 1000000000UL

Crypt::Mac::KMAC
new(Class, const char * variant, SV * key, SV * cust = NULL)
    CODE:
    {
        STRLEN k_len=0, c_len=0;
        unsigned char *k=NULL, *c=NULL;
        int rv;
        int var = -1;

        if (!SvPOK_spec(key)) croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);
        if (cust && SvOK(cust)) {
          if (!SvPOK_spec(cust)) croak("FATAL: cust must be string/buffer scalar");
          c = (unsigned char *) SvPVbyte(cust, c_len);
        }

        if (strcmp(variant, "KMAC128")    == 0) var = LTC_KMAC128;
        if (strcmp(variant, "KMAC256")    == 0) var = LTC_KMAC256;
        if (strcmp(variant, "KMACXOF128") == 0) var = LTC_KMAC128_XOF;
        if (strcmp(variant, "KMACXOF256") == 0) var = LTC_KMAC256_XOF;
        if (var == -1) croak("FATAL: unknown KMAC variant '%s'", variant);

        Newz(0, RETVAL, 1, struct cryptx_mac_kmac_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        rv = kmac_init(&RETVAL->state, var, k, (unsigned long)k_len, c, (unsigned long)c_len);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: kmac_init failed: %s", error_to_string(rv));
        }
        RETVAL->finalized = 0;
        RETVAL->variant = var;
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Mac::KMAC self)
    CODE:
    {
        zeromem(&self->state, sizeof(kmac_state));
        Safefree(self);
    }

Crypt::Mac::KMAC
clone(Crypt::Mac::KMAC self)
    CODE:
        Newz(0, RETVAL, 1, struct cryptx_mac_kmac_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(self, RETVAL, 1, struct cryptx_mac_kmac_struct);
    OUTPUT:
        RETVAL

void
add(Crypt::Mac::KMAC self, ...)
    PPCODE:
    {
        int rv, i;
        STRLEN in_data_len;
        unsigned char *in_data;

        if (self->finalized) croak("FATAL: MAC object already finalized");
        for(i = 1; i < items; i++) {
          in_data = (unsigned char *)SvPVbyte(ST(i), in_data_len);
          if (in_data_len > 0) {
            rv = kmac_process(&self->state, in_data, (unsigned long)in_data_len);
            if (rv != CRYPT_OK) croak("FATAL: kmac_process failed: %s", error_to_string(rv));
          }
        }
        XPUSHs(ST(0)); /* return self */
    }

SV *
mac(Crypt::Mac::KMAC self, unsigned long out_len)
    ALIAS:
        hexmac  = 1
        b64mac  = 2
        b64umac = 3
    CODE:
    {
        unsigned char *mac_buf;
        unsigned long maclen, outlen;
        int rv;
        char *out;

        if (self->finalized) croak("FATAL: MAC object already finalized");
        if (out_len == 0) croak("FATAL: invalid output length");
        if (out_len > CRYPTX_MAC_KMAC_MAX_OUTPUT_LEN) croak("FATAL: output length too large");

        Newz(0, mac_buf, out_len, unsigned char);
        if (!mac_buf) croak("FATAL: Newz failed");
        maclen = out_len;
        rv = kmac_done(&self->state, mac_buf, &maclen);
        if (rv != CRYPT_OK) {
          Safefree(mac_buf);
          croak("FATAL: kmac_done failed: %s", error_to_string(rv));
        }
        self->finalized = 1;

        if (ix == 0) {
          RETVAL = newSVpvn((char *)mac_buf, maclen);
        }
        else {
          /* worst case base16 -> 2x; base64 -> ~4/3x; allocate 2x + 4 to be safe */
          unsigned long buflen = maclen * 2 + 8;
          Newz(0, out, buflen, char);
          if (!out) { Safefree(mac_buf); croak("FATAL: Newz failed"); }
          outlen = buflen;
          if (ix == 3) {
            rv = base64url_encode(mac_buf, maclen, out, &outlen);
            if (rv != CRYPT_OK) { Safefree(mac_buf); Safefree(out); croak("FATAL: base64url_encode failed: %s", error_to_string(rv)); }
          }
          else if (ix == 2) {
            rv = base64_encode(mac_buf, maclen, out, &outlen);
            if (rv != CRYPT_OK) { Safefree(mac_buf); Safefree(out); croak("FATAL: base64_encode failed: %s", error_to_string(rv)); }
          }
          else { /* ix == 1 */
            rv = base16_encode(mac_buf, maclen, out, &outlen, 0);
            if (rv != CRYPT_OK) { Safefree(mac_buf); Safefree(out); croak("FATAL: base16_encode failed: %s", error_to_string(rv)); }
          }
          RETVAL = newSVpvn(out, outlen);
          Safefree(out);
        }
        zeromem(mac_buf, out_len);
        Safefree(mac_buf);
    }
    OUTPUT:
        RETVAL

SV *
kmac(const char * variant, unsigned long out_len, SV * key, SV * cust, ...)
    ALIAS:
        kmac_hex  = 1
        kmac_b64  = 2
        kmac_b64u = 3
    CODE:
    {
        STRLEN inlen, klen, clen=0;
        unsigned char *in, *k, *c=NULL;
        int rv, i;
        int var = -1;
        unsigned char *mac_buf;
        unsigned long maclen, outlen;
        char *out;
        kmac_state st;

        if (!SvPOK_spec(key)) croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *)SvPVbyte(key, klen);
        if (SvOK(cust)) {
          if (!SvPOK_spec(cust)) croak("FATAL: cust must be string/buffer scalar");
          c = (unsigned char *)SvPVbyte(cust, clen);
        }

        if (strcmp(variant, "KMAC128")    == 0) var = LTC_KMAC128;
        if (strcmp(variant, "KMAC256")    == 0) var = LTC_KMAC256;
        if (strcmp(variant, "KMACXOF128") == 0) var = LTC_KMAC128_XOF;
        if (strcmp(variant, "KMACXOF256") == 0) var = LTC_KMAC256_XOF;
        if (var == -1) croak("FATAL: unknown KMAC variant '%s'", variant);
        if (out_len == 0) croak("FATAL: invalid output length");
        if (out_len > CRYPTX_MAC_KMAC_MAX_OUTPUT_LEN) croak("FATAL: output length too large");

        rv = kmac_init(&st, var, k, (unsigned long)klen, c, (unsigned long)clen);
        if (rv != CRYPT_OK) croak("FATAL: kmac_init failed: %s", error_to_string(rv));
        for (i = 4; i < items; i++) {
          in = (unsigned char *)SvPVbyte(ST(i), inlen);
          if (inlen > 0) {
            rv = kmac_process(&st, in, (unsigned long)inlen);
            if (rv != CRYPT_OK) { zeromem(&st, sizeof(st)); croak("FATAL: kmac_process failed: %s", error_to_string(rv)); }
          }
        }
        Newz(0, mac_buf, out_len, unsigned char);
        if (!mac_buf) { zeromem(&st, sizeof(st)); croak("FATAL: Newz failed"); }
        maclen = out_len;
        rv = kmac_done(&st, mac_buf, &maclen);
        zeromem(&st, sizeof(st));
        if (rv != CRYPT_OK) { Safefree(mac_buf); croak("FATAL: kmac_done failed: %s", error_to_string(rv)); }

        if (ix == 0) {
          RETVAL = newSVpvn((char *)mac_buf, maclen);
        }
        else {
          unsigned long buflen = maclen * 2 + 8;
          Newz(0, out, buflen, char);
          if (!out) { Safefree(mac_buf); croak("FATAL: Newz failed"); }
          outlen = buflen;
          if (ix == 3) {
            rv = base64url_encode(mac_buf, maclen, out, &outlen);
            if (rv != CRYPT_OK) { Safefree(mac_buf); Safefree(out); croak("FATAL: base64url_encode failed: %s", error_to_string(rv)); }
          }
          else if (ix == 2) {
            rv = base64_encode(mac_buf, maclen, out, &outlen);
            if (rv != CRYPT_OK) { Safefree(mac_buf); Safefree(out); croak("FATAL: base64_encode failed: %s", error_to_string(rv)); }
          }
          else { /* ix == 1 */
            rv = base16_encode(mac_buf, maclen, out, &outlen, 0);
            if (rv != CRYPT_OK) { Safefree(mac_buf); Safefree(out); croak("FATAL: base16_encode failed: %s", error_to_string(rv)); }
          }
          RETVAL = newSVpvn(out, outlen);
          Safefree(out);
        }
        zeromem(mac_buf, out_len);
        Safefree(mac_buf);
    }
    OUTPUT:
        RETVAL
