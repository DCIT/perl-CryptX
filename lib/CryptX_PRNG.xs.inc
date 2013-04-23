MODULE = CryptX         PACKAGE = Crypt::PRNG

Crypt::PRNG
_new(IV curpid, char * prng_name, SV * entropy=&PL_sv_undef)
    CODE:
    {
        int rv, id;
        unsigned char *ent=NULL;
        STRLEN ent_len=0;
        unsigned char entropy_buf[32];

        Newz(0, RETVAL, 1, struct prng_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        
        id = find_prng(prng_name);
        if(id==-1) croak("FATAL: find_prng failed for '%s'", prng_name);
        RETVAL->id = id;
        RETVAL->last_pid = curpid;
        RETVAL->desc = &prng_descriptor[id];

        rv = RETVAL->desc->start(&RETVAL->state);
        if (rv != CRYPT_OK) croak("FATAL: PRNG_start failed: %s", error_to_string(rv));

        if(SvOK(entropy)) {
          ent = (unsigned char *) SvPVbyte(entropy, ent_len);
          rv = RETVAL->desc->add_entropy(ent, ent_len, &RETVAL->state);
          if (rv != CRYPT_OK) croak("FATAL: PRNG_add_entropy failed: %s", error_to_string(rv));
        }
        else {          
          if (rng_get_bytes(entropy_buf, 32, NULL) != 32) croak("FATAL: rng_get_bytes failed: %s", error_to_string(rv));
          rv = RETVAL->desc->add_entropy(entropy_buf, 32, &RETVAL->state);
          if (rv != CRYPT_OK) croak("FATAL: PRNG_add_entropy failed: %s", error_to_string(rv));
        }
        rv = RETVAL->desc->ready(&RETVAL->state);
        if (rv != CRYPT_OK) croak("FATAL: PRNG_ready failed: %s", error_to_string(rv));
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::PRNG self)
    CODE:
    {
        Safefree(self);
    }

void
add_entropy(Crypt::PRNG self, SV * entropy=&PL_sv_undef)
    CODE:
    {
        STRLEN in_len=0;
        unsigned char *in_buffer=NULL;
        unsigned char entropy_buf[32];
        int rv;
        if(SvOK(entropy)) {
          in_buffer = (unsigned char *) SvPVbyte(entropy, in_len);
          rv = self->desc->add_entropy(in_buffer, in_len, &self->state);
          if (rv != CRYPT_OK) croak("FATAL: PRNG_add_entropy failed: %s", error_to_string(rv));
        }
        else {
          if (rng_get_bytes(entropy_buf, 32, NULL) != 32) croak("FATAL: rng_get_bytes failed");
          rv = self->desc->add_entropy(entropy_buf, 32, &self->state);
          if (rv != CRYPT_OK) croak("FATAL: PRNG_add_entropy failed: %s", error_to_string(rv));
        }
        rv = self->desc->ready(&self->state);
        if (rv != CRYPT_OK) croak("FATAL: PRNG_ready failed: %s", error_to_string(rv));
    }

SV *
_bytes(Crypt::PRNG self, IV curpid, UV output_len)
    CODE:
    {
        int rv_len;
        unsigned char *rdata;
        unsigned char entropy_buf[32];
        
        if (self->last_pid != curpid) {
          rng_get_bytes(entropy_buf, 32, NULL);
          self->desc->add_entropy(entropy_buf, 32, &self->state);
          self->desc->ready(&self->state);
          self->last_pid = curpid;
        }
        
        RETVAL = NEWSV(0, output_len);
        SvPOK_only(RETVAL);
        SvCUR_set(RETVAL, output_len);
        rdata = (unsigned char *)SvPV_nolen(RETVAL);
        rv_len = (self->desc->read)(rdata, output_len, &self->state);
        if ((UV)rv_len != output_len) croak("FATAL: PRNG_read failed");
    }
    OUTPUT:
        RETVAL

UV
_int32(Crypt::PRNG self, IV curpid)
    CODE:
    {
        int i;
        unsigned char rdata[4];
        unsigned char entropy_buf[32];

        if (self->last_pid != curpid) {
          rng_get_bytes(entropy_buf, 32, NULL);
          self->desc->add_entropy(entropy_buf, 32, &self->state);
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
_double(Crypt::PRNG self, IV curpid, ...)
    CODE:
    {
        int i;
        UV a, b;
        unsigned char rdata[7]; /* for double we need 53 bits */
        unsigned char entropy_buf[32];

        if (self->last_pid != curpid) {
          rng_get_bytes(entropy_buf, 32, NULL);
          self->desc->add_entropy(entropy_buf, 32, &self->state);
          self->desc->ready(&self->state);
          self->last_pid = curpid;
        }

        i = (self->desc->read)(rdata, 7, &self->state);
        if (i != 7) croak("FATAL: PRNG_read failed");
        a = (((UV)(rdata[0])<<16) + ((UV)(rdata[1])<<8) + ((UV)(rdata[2]))) & 0x1FFFFF;           /* 21 bits */
        b = ((UV)(rdata[3])<<24) + ((UV)(rdata[4])<<16) + ((UV)(rdata[5])<<8) + ((UV)(rdata[6])); /* 32 bits */
        RETVAL = ( (NV)a * 4294967296.0 + (NV)b ) / 9007199254740992.0;                           /* (a * 2^32 + b) / 2^53 */
        if (items>2 && SvOK(ST(2))) RETVAL = RETVAL * SvNV(ST(2));
    }
    OUTPUT:
        RETVAL
