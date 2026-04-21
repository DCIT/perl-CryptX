MODULE = CryptX         PACKAGE = Crypt::Digest::TurboSHAKE

PROTOTYPES: DISABLE

Crypt::Digest::TurboSHAKE
new(Class, int num)
    CODE:
    {
        int rv;

        Newz(0, RETVAL, 1, struct digest_shake_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        RETVAL->num = num;
        rv = turbo_shake_init(&RETVAL->state, RETVAL->num);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: turbo_shake_init failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Digest::TurboSHAKE self)
    CODE:
        Safefree(self);

void
reset(Crypt::Digest::TurboSHAKE self)
    PPCODE:
    {
        int rv;
        rv = turbo_shake_init(&self->state, self->num);
        if (rv != CRYPT_OK) croak("FATAL: turbo_shake_init failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

Crypt::Digest::TurboSHAKE
clone(Crypt::Digest::TurboSHAKE self)
    CODE:
        Newz(0, RETVAL, 1, struct digest_shake_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(self, RETVAL, 1, struct digest_shake_struct);
    OUTPUT:
        RETVAL

void
add(Crypt::Digest::TurboSHAKE self, ...)
    PPCODE:
    {
        STRLEN inlen;
        int rv, i;
        unsigned char *in;

        for(i=1; i<items; i++) {
          in = (unsigned char *)SvPVbyte(ST(i), inlen);
          if (inlen>0) {
            rv = turbo_shake_process(&self->state, in, (unsigned long)inlen);
            if (rv != CRYPT_OK) croak("FATAL: turbo_shake_process failed: %s", error_to_string(rv));
          }
        }
        XPUSHs(ST(0)); /* return self */
    }

SV *
done(Crypt::Digest::TurboSHAKE self, STRLEN out_len)
    CODE:
    {
        int rv;
        unsigned char *out_data;

        if (out_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          RETVAL = NEWSV(0, out_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, out_len);
          out_data = (unsigned char *)SvPVX(RETVAL);
          rv = turbo_shake_done(&self->state, out_data, (unsigned long)out_len);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: turbo_shake_done failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL
