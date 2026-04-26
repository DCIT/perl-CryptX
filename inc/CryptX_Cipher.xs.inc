MODULE = CryptX         PACKAGE = Crypt::Cipher

PROTOTYPES: DISABLE

Crypt::Cipher
new(char * class, ...)
    CODE:
    {
        STRLEN name_len;
        STRLEN key_len;
        unsigned char *key_data = NULL;
        SV *key;
        SV *name_sv;
        char *cipher_name;
        int rv, id, rounds = 0, idx;

        /* we need to handle:
           Crypt::Cipher->new('AES');
           Crypt::Cipher::AES->new();
        */
        idx = strcmp("Crypt::Cipher", class) == 0 ? 1 : 0;
        if (idx + 1 > items) croak("FATAL: missing argument");
        name_sv = ST(idx);
        if (!SvPOK_spec(name_sv)) croak("FATAL: invalid cipher name");
        cipher_name = SvPVbyte(name_sv, name_len);
        if (idx + 2 > items) croak("FATAL: missing key argument");
        key = ST(idx + 1);
        if (idx + 3 <= items) rounds = (int)SvIV(ST(idx + 2));

        if (!SvPOK_spec(key)) croak("FATAL: key must be string/buffer scalar");
        key_data = (unsigned char *)SvPVbyte(key, key_len);

        id = cryptx_internal_find_cipher(cipher_name);
        if (id == -1) croak("FATAL: find_cipher failed for '%s'", cipher_name);

        Newz(0, RETVAL, 1, struct cipher_struct);
        if (!RETVAL) croak("FATAL: Newz failed");

        RETVAL->desc = &cipher_descriptor[id];
        rv = RETVAL->desc->setup(key_data, (int)key_len, rounds, &RETVAL->skey);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: cipher setup failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Cipher self)
    CODE:
    {
        zeromem(&self->skey, sizeof(symmetric_key));
        Safefree(self);
    }

SV *
encrypt(Crypt::Cipher self, SV * data)
    CODE:
    {
        int rv;
        STRLEN len;
        unsigned char *plaintext;

        if (!SvPOK_spec(data)) XSRETURN_UNDEF;
        plaintext = (unsigned char *)SvPVbyte(data, len);

        if (len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else if (len == (STRLEN)self->desc->block_length) {
          RETVAL = NEWSV(0, len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, len);
          rv = self->desc->ecb_encrypt(plaintext, (unsigned char *)SvPVX(RETVAL), &self->skey);
          if (rv!=CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: encrypt failed: %s", error_to_string(rv));
          }
        }
        else {
          croak ("FATAL: input size not equal to blocksize (%d)", self->desc->block_length);
        }
    }
    OUTPUT:
        RETVAL

SV *
decrypt(Crypt::Cipher self, SV * data)
    CODE:
    {
        int rv;
        STRLEN len;
        unsigned char *ciphertext;

        if (!SvPOK_spec(data)) XSRETURN_UNDEF;
        ciphertext = (unsigned char *)SvPVbyte(data, len);

        if (len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else if (len == (STRLEN)self->desc->block_length) {
          RETVAL = NEWSV(0, len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, len);
          rv = self->desc->ecb_decrypt(ciphertext, (unsigned char *)SvPVX(RETVAL), &self->skey);
          if (rv!=CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: decrypt failed: %s", error_to_string(rv));
          }
        }
        else {
          croak ("FATAL: input size not equal to blocksize (%d)", self->desc->block_length);
        }
    }
    OUTPUT:
        RETVAL

int
blocksize(SV * param, char * extra = NULL)
    CODE:
    {
        if (sv_isobject(param) && sv_derived_from(param, "Crypt::Cipher")) {
          IV tmp = SvIV((SV*)SvRV(param));
          Crypt__Cipher obj = INT2PTR(Crypt__Cipher, tmp);
          RETVAL = obj->desc->block_length;
        }
        else {
          STRLEN plen;
          char *name = SvPOK_spec(param) && strcmp(SvPVbyte(param, plen), "Crypt::Cipher") ? SvPVbyte(param, plen) : extra;
          int rv, id = cryptx_internal_find_cipher(name);
          if (id == -1) croak("FATAL: find_cipher failed for '%s'", name);
          rv = cipher_descriptor[id].block_length;
          if (!rv) croak("FATAL: invalid block_length for '%s'", name);
          RETVAL = rv;
        }
    }
    OUTPUT:
        RETVAL

int
max_keysize(SV * param, char * extra = NULL)
    CODE:
    {
        if (sv_isobject(param) && sv_derived_from(param, "Crypt::Cipher")) {
          IV tmp = SvIV((SV*)SvRV(param));
          Crypt__Cipher obj = INT2PTR(Crypt__Cipher, tmp);
          RETVAL = obj->desc->max_key_length;
        }
        else {
          STRLEN plen;
          char *name = SvPOK_spec(param) && strcmp(SvPVbyte(param, plen), "Crypt::Cipher") ? SvPVbyte(param, plen) : extra;
          int rv, id = cryptx_internal_find_cipher(name);
          if (id == -1) croak("FATAL: find_cipher failed for '%s'", name);
          rv = cipher_descriptor[id].max_key_length;
          if (!rv) croak("FATAL: invalid max_key_length for '%s'", name);
          RETVAL = rv;
        }
    }
    OUTPUT:
        RETVAL

int
min_keysize(SV * param, char * extra = NULL)
    CODE:
    {
        if (sv_isobject(param) && sv_derived_from(param, "Crypt::Cipher")) {
          IV tmp = SvIV((SV*)SvRV(param));
          Crypt__Cipher obj = INT2PTR(Crypt__Cipher, tmp);
          RETVAL = obj->desc->min_key_length;
        }
        else {
          STRLEN plen;
          char *name = SvPOK_spec(param) && strcmp(SvPVbyte(param, plen), "Crypt::Cipher") ? SvPVbyte(param, plen) : extra;
          int rv, id = cryptx_internal_find_cipher(name);
          if (id == -1) croak("FATAL: find_cipher failed for '%s'", name);
          rv = cipher_descriptor[id].min_key_length;
          if (!rv) croak("FATAL: invalid min_key_length for '%s'", name);
          RETVAL = rv;
        }
    }
    OUTPUT:
        RETVAL

int
default_rounds(SV * param, char * extra = NULL)
    CODE:
    {
        if (sv_isobject(param) && sv_derived_from(param, "Crypt::Cipher")) {
          IV tmp = SvIV((SV*)SvRV(param));
          Crypt__Cipher obj = INT2PTR(Crypt__Cipher, tmp);
          RETVAL = obj->desc->default_rounds;
        }
        else {
          STRLEN plen;
          char *name = SvPOK_spec(param) && strcmp(SvPVbyte(param, plen), "Crypt::Cipher") ? SvPVbyte(param, plen) : extra;
          int rv, id = cryptx_internal_find_cipher(name);
          if (id == -1) croak("FATAL: find_cipher failed for '%s'", name);
          rv = cipher_descriptor[id].default_rounds;
          if (!rv) XSRETURN_UNDEF;
          RETVAL = rv;
        }
    }
    OUTPUT:
        RETVAL
