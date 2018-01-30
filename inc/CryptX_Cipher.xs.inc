MODULE = CryptX         PACKAGE = Crypt::Cipher

PROTOTYPES: DISABLE

Crypt::Cipher
new(char * class, ...)
    CODE:
    {
        STRLEN key_len;
        unsigned char *key_data = NULL;
        SV *key;
        char *cipher_name;
        int rv, id, rounds = 0, idx;

        /* we need to handle:
           Crypt::Cipher->new('AES');
           Crypt::Cipher::AES->new();
         */
        idx = strcmp("Crypt::Cipher", class) == 0 ? 1 : 0;
        if (idx + 1 > items) croak("FATAL: missing argument");
        cipher_name = SvPVX(ST(idx));
        key = ST(idx + 1);
        if (idx + 3 <= items) rounds = (int)SvIV(ST(idx + 2));

        if (!SvPOK (key)) croak("FATAL: key must be string scalar");
        key_data = (unsigned char *)SvPVbyte(key, key_len);

        id = _find_cipher(cipher_name);
        if (id == -1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);

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
        Safefree(self);

SV *
encrypt(Crypt::Cipher self, SV * data)
    CODE:
    {
        int rv;
        STRLEN len;
        void *plaintext = SvPVbyte(data, len);

        if (len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else if (len == (STRLEN)self->desc->block_length) {
          RETVAL = NEWSV(0, len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, len);
          rv = self->desc->ecb_encrypt((unsigned char *)plaintext, (unsigned char *)SvPVX(RETVAL), &self->skey);
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
        void *ciphertext = SvPVbyte(data, len);

        if (len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else if (len == (STRLEN)self->desc->block_length) {
          RETVAL = NEWSV(0, len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, len);
          rv = self->desc->ecb_decrypt((unsigned char *)ciphertext, (unsigned char *)SvPVX(RETVAL), &self->skey);
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
          char *name = SvPOK(param) && strcmp(SvPVX(param), "Crypt::Cipher") ? SvPVX(param) : extra;
          int rv, id = _find_cipher(name);
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
          char *name = SvPOK(param) && strcmp(SvPVX(param), "Crypt::Cipher") ? SvPVX(param) : extra;
          int rv, id = _find_cipher(name);
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
          char *name = SvPOK(param) && strcmp(SvPVX(param), "Crypt::Cipher") ? SvPVX(param) : extra;
          int rv, id = _find_cipher(name);
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
          char *name = SvPOK(param) && strcmp(SvPVX(param), "Crypt::Cipher") ? SvPVX(param) : extra;
          int rv, id = _find_cipher(name);
          if (id == -1) croak("FATAL: find_cipher failed for '%s'", name);
          rv = cipher_descriptor[id].default_rounds;
          if (!rv) XSRETURN_UNDEF;
          RETVAL = rv;
        }
    }
    OUTPUT:
        RETVAL
