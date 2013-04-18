MODULE = CryptX         PACKAGE = Crypt::PRNG

Crypt::PRNG
_new(char * prng_name, SV * entropy=&PL_sv_undef)
    CODE:
    {
        int rv, id;
        unsigned char *ent=NULL;
        STRLEN ent_len=0;

        Newz(0, RETVAL, 1, struct prng_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        
        id = find_prng(prng_name);
        if(id==-1) croak("FATAL: find_prng failed for '%s'", prng_name);
        RETVAL->id = id;
        RETVAL->desc = &prng_descriptor[id];

        if(SvOK(entropy)) {
          ent = (unsigned char *) SvPVbyte(entropy, ent_len);
          rv = RETVAL->desc->start(&RETVAL->state);
          if (rv != CRYPT_OK) croak("FATAL: PRNG_start failed: %s", error_to_string(rv));
          rv = RETVAL->desc->add_entropy(ent, ent_len, &RETVAL->state);
          if (rv != CRYPT_OK) croak("FATAL: PRNG_add_entropy failed: %s", error_to_string(rv));
        }
        else {          
          rv = rng_make_prng(128, id, &RETVAL->state, NULL);
          if (rv != CRYPT_OK) croak("FATAL: rng_make_prng failed: %s", error_to_string(rv));
        }
        rv = RETVAL->desc->ready(&RETVAL->state);
        if (rv != CRYPT_OK) croak("FATAL: PRNG_ready failed: %s", error_to_string(rv));
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::PRNG self)
    CODE:
        Safefree(self);

void
add_entropy(Crypt::PRNG self, SV * in)
    CODE:
    {
        STRLEN in_len=0;
        unsigned char *in_buffer=NULL;
        int rv;
        if (!SvPOK(in)) croak("FATAL: 'in' must be string/buffer scalar");
        in_buffer = (unsigned char *) SvPVbyte(in, in_len);
        rv = self->desc->add_entropy(in_buffer, in_len, &self->state);
        if (rv != CRYPT_OK) croak("FATAL: PRNG_add_entropy failed: %s", error_to_string(rv));
    }

SV *
bytes(Crypt::PRNG self, UV output_len)
    CODE:
    {
        int rv_len;
        unsigned char *rdata;
        RETVAL = NEWSV(0, output_len);
        SvPOK_only(RETVAL);
        SvCUR_set(RETVAL, output_len);
        rdata = (unsigned char *)SvPV_nolen(RETVAL);
        rv_len = (self->desc->read)(rdata, output_len, &self->state);
        if (rv_len != output_len) croak("FATAL: PRNG_read failed");
    }
    OUTPUT:
        RETVAL

UV
int32(Crypt::PRNG self)
    CODE:
    {
        int i;
        unsigned char rdata[4];
        i = (self->desc->read)(rdata, 4, &self->state);
        if (i != 4) croak("FATAL: PRNG_read failed");
        RETVAL = ((UV)(rdata[0])<<24) + ((UV)(rdata[1])<<16) + ((UV)(rdata[2])<<8) + ((UV)(rdata[3]));
    }
    OUTPUT:
        RETVAL

NV
double(Crypt::PRNG self, NV limit=1)
    CODE:
    {
        int i;
        UV a, b;
        unsigned char rdata[7]; /* for double we need 53 bits */
        i = (self->desc->read)(rdata, 7, &self->state);
        if (i != 7) croak("FATAL: PRNG_read failed");
        a = (((UV)(rdata[0])<<16) + ((UV)(rdata[1])<<8) + ((UV)(rdata[2]))) & 0x1FFFFF;           /* 21 bits */
        b = ((UV)(rdata[3])<<24) + ((UV)(rdata[4])<<16) + ((UV)(rdata[5])<<8) + ((UV)(rdata[6])); /* 32 bits */
        RETVAL = ( (NV)a * 4294967296.0 + (NV)b ) / 9007199254740992.0;                           /* (a * 2^32 + b) / 2^53 */
        if (items>1) RETVAL = RETVAL * limit;
    }
    OUTPUT:
        RETVAL
