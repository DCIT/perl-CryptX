MODULE = CryptX         PACKAGE = Crypt::PRNG

PROTOTYPES: DISABLE

Crypt::PRNG
new(char * class, ...)
    CODE:
    {
        IV curpid = (IV)PerlProc_getpid();
        int rv, id, idx;
        unsigned char *ent=NULL;
        STRLEN ent_len=0;
        unsigned char entropy_buf[40];
        char *prng_name = (char *)"ChaCha20";
        SV *entropy = &PL_sv_undef;

        /* we need to handle:
           Crypt::PRNG->new('RC4');
           Crypt::Cipher::RC4->new();
         */
        idx = strcmp("Crypt::PRNG", class) == 0 ? 1 : 0;
        if (idx + 1 <= items) prng_name = SvPVX(ST(idx));
        if (idx + 2 <= items) entropy = ST(idx + 1);

        Newz(0, RETVAL, 1, struct prng_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        id = _find_prng(prng_name);
        if (id == -1) {
          Safefree(RETVAL);
          croak("FATAL: find_prng failed for '%s'", prng_name);
        }
        RETVAL->last_pid = curpid;
        RETVAL->desc = &prng_descriptor[id];

        rv = RETVAL->desc->start(&RETVAL->state);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: PRNG_start failed: %s", error_to_string(rv));
        }

        if (SvOK(entropy)) {
          ent = (unsigned char *) SvPVbyte(entropy, ent_len);
          rv = RETVAL->desc->add_entropy(ent, (unsigned long)ent_len, &RETVAL->state);
          if (rv != CRYPT_OK) {
            Safefree(RETVAL);
            croak("FATAL: PRNG_add_entropy failed: %s", error_to_string(rv));
          }
        }
        else {
          if (rng_get_bytes(entropy_buf, 40, NULL) != 40) {
            Safefree(RETVAL);
            croak("FATAL: rng_get_bytes failed: %s", error_to_string(rv));
          }
          rv = RETVAL->desc->add_entropy(entropy_buf, 40, &RETVAL->state);
          if (rv != CRYPT_OK) {
            Safefree(RETVAL);
            croak("FATAL: PRNG_add_entropy failed: %s", error_to_string(rv));
          }
        }
        rv = RETVAL->desc->ready(&RETVAL->state);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: PRNG_ready failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::PRNG self)
    CODE:
        Safefree(self);

void
add_entropy(Crypt::PRNG self, SV * entropy=&PL_sv_undef)
    CODE:
    {
        STRLEN in_len=0;
        unsigned char *in_buffer=NULL;
        unsigned char entropy_buf[40];
        int rv;
        if (SvOK(entropy)) {
          in_buffer = (unsigned char *) SvPVbyte(entropy, in_len);
          rv = self->desc->add_entropy(in_buffer, (unsigned long)in_len, &self->state);
          if (rv != CRYPT_OK) croak("FATAL: PRNG_add_entropy failed: %s", error_to_string(rv));
        }
        else {
          if (rng_get_bytes(entropy_buf, 40, NULL) != 40) croak("FATAL: rng_get_bytes failed");
          rv = self->desc->add_entropy(entropy_buf, 40, &self->state);
          if (rv != CRYPT_OK) croak("FATAL: PRNG_add_entropy failed: %s", error_to_string(rv));
        }
        rv = self->desc->ready(&self->state);
        if (rv != CRYPT_OK) croak("FATAL: PRNG_ready failed: %s", error_to_string(rv));
    }

SV *
bytes(Crypt::PRNG self, unsigned long output_len)
    ALIAS:
        bytes_hex  = 1
        bytes_b64  = 2
        bytes_b64u = 3
    CODE:
    {
        IV curpid = (IV)PerlProc_getpid();
        int rv_len, rv;
        unsigned long len;
        unsigned char *tmp;
        char *rdata;
        unsigned char entropy_buf[40];

        if (output_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          if (self->last_pid != curpid) {
            if (rng_get_bytes(entropy_buf, 40, NULL) != 40) croak("FATAL: rng_get_bytes failed");
            self->desc->add_entropy(entropy_buf, 40, &self->state);
            self->desc->ready(&self->state);
            self->last_pid = curpid;
          }
          if (ix == 1) {
            /* HEX */
            Newz(0, tmp, output_len, unsigned char);
            if (tmp == NULL) croak("FATAL: Newz failed");
            rv_len = (self->desc->read)(tmp, (unsigned long)output_len, &self->state);
            if ((UV)rv_len != output_len) croak("FATAL: PRNG_read failed");
            RETVAL = NEWSV(0, output_len * 2 + 1); /* avoid zero! */
            SvPOK_only(RETVAL);
            SvCUR_set(RETVAL, output_len * 2 + 1);
            rdata = SvPVX(RETVAL);
            len = output_len * 2 + 1;
            rv = base16_encode(tmp, output_len, rdata, &len, 0);
            SvCUR_set(RETVAL, len);
            Safefree(tmp);
            if (rv != CRYPT_OK) {
              SvREFCNT_dec(RETVAL);
              croak("FATAL: base16_encode failed");
            }
          }
          else if (ix == 2 || ix == 3) {
            /* BASE64 or BASE64URL */
            Newz(0, tmp, output_len, unsigned char);
            if (tmp == NULL) croak("FATAL: Newz failed");
            rv_len = (self->desc->read)(tmp, (unsigned long)output_len, &self->state);
            if ((UV)rv_len != output_len) croak("FATAL: PRNG_read failed");
            RETVAL = NEWSV(0, output_len * 2); /* avoid zero! */
            SvPOK_only(RETVAL);
            SvCUR_set(RETVAL, output_len * 2);
            rdata = SvPVX(RETVAL);
            len = output_len * 2;
            rv = ix == 3 ? base64url_encode(tmp, output_len, rdata, &len) :
                           base64_encode(tmp, output_len, rdata, &len);
            SvCUR_set(RETVAL, len);
            Safefree(tmp);
            if (rv != CRYPT_OK) {
              SvREFCNT_dec(RETVAL);
              croak(ix == 3 ? "FATAL: base64url_encode failed" : "FATAL: base64_encode failed");
            }
          }
          else {
            /* RAW BYTES */
            RETVAL = NEWSV(0, output_len); /* avoid zero! */
            SvPOK_only(RETVAL);
            SvCUR_set(RETVAL, output_len);
            rdata = SvPVX(RETVAL);
            rv_len = (self->desc->read)((unsigned char*)rdata, (unsigned long)output_len, &self->state);
            if ((UV)rv_len != output_len) {
              SvREFCNT_dec(RETVAL);
              croak("FATAL: PRNG_read failed");
            }
          }
        }
    }
    OUTPUT:
        RETVAL

UV
int32(Crypt::PRNG self)
    CODE:
    {
        IV curpid = (IV)PerlProc_getpid();
        int i;
        unsigned char rdata[4];
        unsigned char entropy_buf[40];

        if (self->last_pid != curpid) {
          if (rng_get_bytes(entropy_buf, 40, NULL) != 40) croak("FATAL: rng_get_bytes failed");
          self->desc->add_entropy(entropy_buf, 40, &self->state);
          self->desc->ready(&self->state);
          self->last_pid = curpid;
        }

        i = (self->desc->read)(rdata, 4, &self->state);
        if (i != 4) croak("FATAL: PRNG_read failed");
        RETVAL = ((UV)(rdata[0])<<24) + ((UV)(rdata[1])<<16) + ((UV)(rdata[2])<<8) + ((UV)(rdata[3]));
    }
    OUTPUT:
        RETVAL

NV
double(Crypt::PRNG self, SV * limit_sv = NULL)
    CODE:
    {
        IV curpid = (IV)PerlProc_getpid();
        int i;
        unsigned long a, b;     /* 32bit is enough */
        unsigned char rdata[7]; /* for double we need 53 bits */
        unsigned char entropy_buf[40];

        if (self->last_pid != curpid) {
          if (rng_get_bytes(entropy_buf, 40, NULL) != 40) croak("FATAL: rng_get_bytes failed");
          self->desc->add_entropy(entropy_buf, 40, &self->state);
          self->desc->ready(&self->state);
          self->last_pid = curpid;
        }

        i = (self->desc->read)(rdata, 7, &self->state);
        if (i != 7) croak("FATAL: PRNG_read failed");
        a = (((unsigned long)(rdata[0])<<16) + ((unsigned long)(rdata[1])<<8) + ((unsigned long)(rdata[2]))) & 0x1FFFFF;                      /* 21 bits */
        b = ((unsigned long)(rdata[3])<<24) + ((unsigned long)(rdata[4])<<16) + ((unsigned long)(rdata[5])<<8) + ((unsigned long)(rdata[6])); /* 32 bits */
        RETVAL = ( (NV)a * 4294967296.0 + (NV)b ) / 9007199254740992.0;                           /* (a * 2^32 + b) / 2^53 */
        if (limit_sv && SvOK(limit_sv)) {
          NV limit = SvNV(limit_sv);
          if (limit > 0 || limit < 0) RETVAL = RETVAL * limit;
        }
    }
    OUTPUT:
        RETVAL
