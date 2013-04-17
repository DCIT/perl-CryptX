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
        unsigned char *out_data;
        RETVAL = NEWSV(0, output_len);
        SvPOK_only(RETVAL);
        SvCUR_set(RETVAL, output_len);
        out_data = (unsigned char *)SvPV_nolen(RETVAL);
        rv_len = (self->desc->read)(out_data, output_len, &self->state);
        if (rv_len != output_len) croak("FATAL: PRNG_read failed");
    }
    OUTPUT:
        RETVAL

UV
irand(Crypt::PRNG self)
    CODE:
    {
        int i;
        UV u;
        unsigned char out_data[4];
        i = (self->desc->read)(out_data, 4, &self->state);
        if (i != sizeof(UV)) croak("FATAL: PRNG_read failed");
        for(i=0, u=0; i<sizeof(UV); i++) u += (UV)(out_data[i]) << i*8;
        RETVAL = ((UV)(out_data[0])<<24) + ((UV)(out_data[1])<<16) + ((UV)(out_data[2])<<8) + ((UV)(out_data[3]));
    }
    OUTPUT:
        RETVAL

NV
rand(Crypt::PRNG self, NV limit=1)
    CODE:
    {
        int i;
        UV u;
        unsigned char out_data[sizeof(UV)];
        i = (self->desc->read)(out_data, sizeof(UV), &self->state);
        if (i != sizeof(UV)) croak("FATAL: PRNG_read failed");
        for(i=0, u=0; i<sizeof(UV); i++) u += (UV)(out_data[i]) << i*8;
        RETVAL = 0;
        if (sizeof(u) == 8) { /* 64bit int */
          u = u >> 12;
          RETVAL = (NV)u * (NV)2.220446049250313080847263336181640625e-16;  /* RETVAL = u>>12 / 2^52 */
          if (items>1) RETVAL = RETVAL * limit;
        }
        else if (sizeof(u) == 4) { /* 32bit int */
          RETVAL = (NV)u * (NV)2.3283064365386962890625e-10;       /* RETVAL = u / 2^32 */
          if (items>1) RETVAL = RETVAL * limit;
        }
    }
    OUTPUT:
        RETVAL
