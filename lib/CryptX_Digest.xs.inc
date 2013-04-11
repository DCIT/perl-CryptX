MODULE = CryptX         PACKAGE = Crypt::Digest

Crypt::Digest
_new(digest_name)
        char * digest_name
    CODE:
    {
        int rv;
        int id;

        id = find_hash(digest_name);
        if(id==-1) croak("FATAL: find_hash failed for '%s'", digest_name);

        Newz(0, RETVAL, 1, struct digest_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        RETVAL->id = id;
        RETVAL->desc = &hash_descriptor[id];
        rv = RETVAL->desc->init(&RETVAL->state);
        if(rv!=CRYPT_OK) croak("FATAL: digest setup failed: %s", error_to_string(rv));
    }
    OUTPUT:
        RETVAL

void
DESTROY(self)
        Crypt::Digest self
    CODE:
        Safefree(self);

void
reset(self)
    Crypt::Digest self
    CODE:
    {
        int rv;
        rv = self->desc->init(&self->state);
        if (rv != CRYPT_OK) croak("FATAL: digest init failed: %s", error_to_string(rv));
    }

Crypt::Digest
clone(self)
    Crypt::Digest self
    CODE:
        Newz(0, RETVAL, 1, struct digest_struct);
        Copy(&self->state, &RETVAL->state, 1, struct digest_struct);
    OUTPUT:
        RETVAL

void
_add_single(self, data)
        Crypt::Digest self
        SV * data
    CODE:
    {
        STRLEN inlen;
        int rv;
        unsigned char *in;
        
        in = (unsigned char *)SvPVbyte(data, inlen);
        rv = self->desc->process(&self->state, in, inlen);
        if (rv != CRYPT_OK) croak("FATAL: digest process failed: %s", error_to_string(rv));
    }

SV *
digest(self)
        Crypt::Digest self
    CODE:
    {
        unsigned char hash[MAXBLOCKSIZE];
        int rv;
        
        rv = self->desc->done(&self->state, hash);
        if (rv != CRYPT_OK) croak("FATAL: digest done failed: %s", error_to_string(rv));
        RETVAL = newSVpv((char *) hash, self->desc->hashsize);
    }
    OUTPUT:
        RETVAL

SV *
hexdigest(self)
        Crypt::Digest self
    CODE:
    {
        int rv, i;
        unsigned char hash[MAXBLOCKSIZE];
        char hash_hex[MAXBLOCKSIZE*2 + 1];
        
        rv = self->desc->done(&self->state, hash);
        if (rv != CRYPT_OK) croak("FATAL: digest done failed: %s", error_to_string(rv));
        
        hash_hex[0] = '\0';
        for(i=0; i<self->desc->hashsize; i++)
            sprintf(&hash_hex[2*i], "%02x", hash[i]);
        RETVAL = newSVpv(hash_hex, strlen(hash_hex));
    }
    OUTPUT:
        RETVAL

SV *
b64digest(self)
        Crypt::Digest self
    CODE:
    {
        int rv;
        unsigned long outlen;
        unsigned char hash[MAXBLOCKSIZE];
        char hash_base64[MAXBLOCKSIZE*2 + 1];
        
        rv = self->desc->done(&self->state, hash);
        if (rv != CRYPT_OK) croak("FATAL: digest done failed: %s", error_to_string(rv));
        
        outlen = sizeof(hash_base64);
        rv = base64_encode(hash, self->desc->hashsize, (unsigned char *)hash_base64, &outlen);
        if (rv != CRYPT_OK) croak("FATAL: base64_encode failed: %s", error_to_string(rv));
        RETVAL = newSVpv(hash_base64, outlen);
    }
    OUTPUT:
        RETVAL

int
_hashsize(self)
        Crypt::Digest self
    CODE:
        RETVAL = self->desc->hashsize;
    OUTPUT:
        RETVAL

int
_hashsize_by_name(digest_name)
        char * digest_name
    CODE:
    {
        int rv, id;
        
        id = find_hash(digest_name);
        if(id==-1) croak("FATAL: find_digest failed for '%s'", digest_name);
        
        rv = hash_descriptor[id].hashsize;
        if (!rv) croak("FATAL: invalid hashsize for '%s'", digest_name);;
        RETVAL = rv;
    }
    OUTPUT:
        RETVAL
