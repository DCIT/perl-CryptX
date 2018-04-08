MODULE = CryptX         PACKAGE = Crypt::Digest

PROTOTYPES: DISABLE

Crypt::Digest
new(char * cname, char * pname = NULL)
    CODE:
    {
        int rv;
        int id;
        char *digest_name = strcmp(cname, "Crypt::Digest") == 0 ? pname : cname;

        id = _find_hash(digest_name);
        if (id == -1) croak("FATAL: find_hash failed for '%s'", digest_name);

        Newz(0, RETVAL, 1, struct digest_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        RETVAL->desc = &hash_descriptor[id];
        rv = RETVAL->desc->init(&RETVAL->state);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: digest setup failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Digest self)
    CODE:
        Safefree(self);

void
reset(Crypt::Digest self)
    PPCODE:
    {
        int rv;
        rv = self->desc->init(&self->state);
        if (rv != CRYPT_OK) croak("FATAL: digest init failed: %s", error_to_string(rv));
        XPUSHs(ST(0)); /* return self */
    }

Crypt::Digest
clone(Crypt::Digest self)
    CODE:
        Newz(0, RETVAL, 1, struct digest_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        Copy(&self->state, &RETVAL->state, 1, struct digest_struct);
    OUTPUT:
        RETVAL

void
add(Crypt::Digest self, ...)
    PPCODE:
    {
        STRLEN inlen;
        int rv, i;
        unsigned char *in;

        for(i = 1; i < items; i++) {
          in = (unsigned char *)SvPVbyte(ST(i), inlen);
          if (inlen > 0) {
            rv = self->desc->process(&self->state, in, (unsigned long)inlen);
            if (rv != CRYPT_OK) croak("FATAL: digest process failed: %s", error_to_string(rv));
          }
        }
        XPUSHs(ST(0)); /* return self */
    }

SV *
digest(Crypt::Digest self)
    ALIAS:
        hexdigest  = 1
        b64digest  = 2
        b64udigest = 3
    CODE:
    {
        int rv;
        unsigned long outlen;
        unsigned char hash[MAXBLOCKSIZE];
        char out[MAXBLOCKSIZE*2+1];

        rv = self->desc->done(&self->state, hash);
        if (rv != CRYPT_OK) croak("FATAL: digest done failed: %s", error_to_string(rv));

        outlen = sizeof(out);
        if (ix == 3) {
          rv = base64url_encode(hash, self->desc->hashsize, out, &outlen);
          if (rv != CRYPT_OK) croak("FATAL: base64url_encode failed: %s", error_to_string(rv));
          RETVAL = newSVpvn(out, outlen);
        }
        else if (ix == 2) {
          rv = base64_encode(hash, self->desc->hashsize, out, &outlen);
          if (rv != CRYPT_OK) croak("FATAL: base64_encode failed: %s", error_to_string(rv));
          RETVAL = newSVpvn(out, outlen);
        }
        else if (ix == 1) {
          rv = base16_encode(hash, self->desc->hashsize, out, &outlen, 0);
          if (rv != CRYPT_OK) croak("FATAL: base16_encode failed: %s", error_to_string(rv));
          RETVAL = newSVpvn(out, outlen);
        }
        else {
          RETVAL = newSVpvn((char *) hash, self->desc->hashsize);
        }
    }
    OUTPUT:
        RETVAL

SV *
digest_data(char * digest_name, ...)
    ALIAS:
        digest_data_hex  = 1
        digest_data_b64  = 2
        digest_data_b64u = 3
    CODE:
    {
        STRLEN inlen;
        int rv, id, i;
        unsigned char *in, hash[MAXBLOCKSIZE];
        unsigned long len = sizeof(hash), outlen;
        char out[MAXBLOCKSIZE*2+1];
        hash_state md;

        id = _find_hash(digest_name);
        if (id == -1) croak("FATAL: find_digest failed for '%s'", digest_name);

        /* digest_data("SHA1", $data1, $data2, $data3); */
        len = hash_descriptor[id].hashsize;
        rv = hash_descriptor[id].init(&md);
        if (rv != CRYPT_OK) croak("FATAL: digest init failed: %s", error_to_string(rv));
        for (i = 1; i < items; i++) {
          in = (unsigned char *)SvPVbyte(ST(i), inlen);
          if (inlen > 0) {
            rv = hash_descriptor[id].process(&md, in, (unsigned long)inlen);
            if (rv != CRYPT_OK) croak("FATAL: digest process failed: %s", error_to_string(rv));
          }
        }
        rv = hash_descriptor[id].done(&md, hash);
        if (rv != CRYPT_OK) croak("FATAL: digest done failed: %s", error_to_string(rv));

        outlen = sizeof(out);
        if (ix == 3) {
          rv = base64url_encode(hash, len, out, &outlen);
          if (rv != CRYPT_OK) croak("FATAL: base64url_encode failed: %s", error_to_string(rv));
          RETVAL = newSVpvn(out, outlen);
        }
        else if (ix == 2) {
          rv = base64_encode(hash, len, out, &outlen);
          if (rv != CRYPT_OK) croak("FATAL: base64_encode failed: %s", error_to_string(rv));
          RETVAL = newSVpvn(out, outlen);
        }
        else if (ix == 1) {
          rv = base16_encode(hash, len, out, &outlen, 0);
          if (rv != CRYPT_OK) croak("FATAL: base16_encode failed: %s", error_to_string(rv));
          RETVAL = newSVpvn(out, outlen);
        }
        else {
          RETVAL = newSVpvn((char *) hash, len);
        }
    }
    OUTPUT:
        RETVAL

int
hashsize(SV * param, char * extra = NULL)
    CODE:
    {
        if (sv_isobject(param) && sv_derived_from(param, "Crypt::Digest")) {
          IV tmp = SvIV((SV*)SvRV(param));
          Crypt__Digest obj = INT2PTR(Crypt__Digest, tmp);
          RETVAL = obj->desc->hashsize;
        }
        else {
          char *digest_name;
          int rv, id;
          digest_name = SvPOK(param) && strcmp(SvPVX(param), "Crypt::Digest") ? SvPVX(param) : extra;
          id = _find_hash(digest_name);
          if (id == -1) croak("FATAL: find_hash failed for '%s'", digest_name);
          rv = hash_descriptor[id].hashsize;
          if (!rv) croak("FATAL: invalid hashsize for '%s'", digest_name);;
          RETVAL = rv;
        }
    }
    OUTPUT:
        RETVAL
