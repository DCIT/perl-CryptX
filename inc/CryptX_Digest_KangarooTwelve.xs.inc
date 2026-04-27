MODULE = CryptX         PACKAGE = Crypt::Digest::KangarooTwelve

PROTOTYPES: DISABLE

#define CRYPTX_DIGEST_KANGAROOTWELVE_MAX_OUTPUT_LEN 1000000000UL

Crypt::Digest::KangarooTwelve
new(Class, int num)
    CODE:
    {
        int rv;

        Newz(0, RETVAL, 1, struct digest_shake_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        RETVAL->num = num;
        RETVAL->squeezing = 0;
        rv = kangaroo_twelve_init(&RETVAL->state, RETVAL->num);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: kangaroo_twelve_init failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Digest::KangarooTwelve self)
    CODE:
        Safefree(self);

void
reset(Crypt::Digest::KangarooTwelve self)
    PPCODE:
    {
        int rv;
        rv = kangaroo_twelve_init(&self->state, self->num);
        if (rv != CRYPT_OK) croak("FATAL: kangaroo_twelve_init failed: %s", error_to_string(rv));
        self->squeezing = 0;
        XPUSHs(ST(0)); /* return self */
    }

Crypt::Digest::KangarooTwelve
clone(Crypt::Digest::KangarooTwelve self)
    CODE:
        Newz(0, RETVAL, 1, struct digest_shake_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(self, RETVAL, 1, struct digest_shake_struct);
    OUTPUT:
        RETVAL

void
add(Crypt::Digest::KangarooTwelve self, ...)
    PPCODE:
    {
        STRLEN inlen;
        int rv, i;
        unsigned char *in;

        if (self->squeezing) croak("FATAL: cannot add after done; call reset first");

        for(i=1; i<items; i++) {
          in = (unsigned char *)SvPVbyte(ST(i), inlen);
          if (inlen>0) {
            rv = kangaroo_twelve_process(&self->state, in, (unsigned long)inlen);
            if (rv != CRYPT_OK) croak("FATAL: kangaroo_twelve_process failed: %s", error_to_string(rv));
          }
        }
        XPUSHs(ST(0)); /* return self */
    }

void
customization(Crypt::Digest::KangarooTwelve self, ...)
    PPCODE:
    {
        STRLEN inlen;
        int rv, i;
        unsigned char *in;

        if (self->squeezing) croak("FATAL: cannot add after done; call reset first");

        for(i=1; i<items; i++) {
          in = (unsigned char *)SvPVbyte(ST(i), inlen);
          if (inlen>0) {
            rv = kangaroo_twelve_customization(&self->state, in, (unsigned long)inlen);
            if (rv != CRYPT_OK) croak("FATAL: kangaroo_twelve_customization failed: %s", error_to_string(rv));
          }
        }
        XPUSHs(ST(0)); /* return self */
    }

SV *
done(Crypt::Digest::KangarooTwelve self, unsigned long out_len)
    CODE:
    {
        int rv;
        unsigned char *out_data;

        if (out_len == 0) croak("FATAL: invalid output length");
        if (out_len > CRYPTX_DIGEST_KANGAROOTWELVE_MAX_OUTPUT_LEN) croak("FATAL: output length too large");
        RETVAL = NEWSV(0, out_len); /* avoid zero! */
        SvPOK_only(RETVAL);
        SvCUR_set(RETVAL, out_len);
        out_data = (unsigned char *)SvPVX(RETVAL);
        rv = kangaroo_twelve_done(&self->state, out_data, out_len);
        if (rv != CRYPT_OK) {
          SvREFCNT_dec(RETVAL);
          croak("FATAL: kangaroo_twelve_done failed: %s", error_to_string(rv));
        }
        self->squeezing = 1;
    }
    OUTPUT:
        RETVAL
