MODULE = CryptX         PACKAGE = Crypt::Mode::CTR

PROTOTYPES: DISABLE

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

Crypt::Mode::CTR
new(Class, char * cipher_name, int ctr_mode=0, int ctr_width=0, int rounds=0)
    CODE:
    {
        Newz(0, RETVAL, 1, struct ctr_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        RETVAL->direction = 0;
        RETVAL->cipher_rounds = rounds;
        RETVAL->cipher_id = _find_cipher(cipher_name);
        if (RETVAL->cipher_id == -1) {
          Safefree(RETVAL);
          croak("FATAL: find_cipfer failed for '%s'", cipher_name);
        }
        if (ctr_mode == 0) RETVAL->ctr_mode_param = CTR_COUNTER_LITTLE_ENDIAN;
        if (ctr_mode == 1) RETVAL->ctr_mode_param = CTR_COUNTER_BIG_ENDIAN;
        if (ctr_mode == 2) RETVAL->ctr_mode_param = CTR_COUNTER_LITTLE_ENDIAN|LTC_CTR_RFC3686;
        if (ctr_mode == 3) RETVAL->ctr_mode_param = CTR_COUNTER_BIG_ENDIAN|LTC_CTR_RFC3686;
        if (ctr_width > 0 && ctr_width <= cipher_descriptor[RETVAL->cipher_id].block_length) RETVAL->ctr_mode_param |= ctr_width;
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Mode::CTR self)
    CODE:
        Safefree(self);

void
start_decrypt(Crypt::Mode::CTR self, SV * key, SV * iv)
    ALIAS:
        start_encrypt = 1
    PPCODE:
    {
        STRLEN k_len=0;
        unsigned char *k=NULL;
        STRLEN i_len=0;
        unsigned char *i=NULL;
        int rv;

        if (!SvPOK(key))   croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);

        if (!SvPOK(iv))    croak("FATAL: iv must be string/buffer scalar");
        i = (unsigned char *) SvPVbyte(iv, i_len);
        if (i_len != (STRLEN)cipher_descriptor[self->cipher_id].block_length) {
          croak ("FATAL: sizeof(iv) should be equal to blocksize (%d)", cipher_descriptor[self->cipher_id].block_length);
        }

        rv = ctr_start(self->cipher_id, i, k, (int)k_len, self->cipher_rounds, self->ctr_mode_param, &self->state);
        if (rv != CRYPT_OK) {
          croak("FATAL: ctr_start failed: %s", error_to_string(rv));
        }

        self->direction = ix == 1 ? 1 : -1;
        XPUSHs(ST(0)); /* return self */
    }

SV *
add(Crypt::Mode::CTR self, ...)
    CODE:
    {
        int rv, j;
        STRLEN in_data_len, out_len = 0;
        unsigned char *in_data, *out_data;

        RETVAL = newSVpvn("", 0);
        for (j = 1; j < items; j++) {
          in_data = (unsigned char *)SvPVbyte(ST(j), in_data_len);
          if (in_data_len > 0) {
            out_data = (unsigned char*)SvGROW(RETVAL, out_len + in_data_len + 1) + out_len;
            out_len += in_data_len;
            if (self->direction == 1) {
              rv = ctr_encrypt(in_data, out_data, (unsigned long)in_data_len, &self->state);
              if (rv != CRYPT_OK) {
                SvREFCNT_dec(RETVAL);
                croak("FATAL: ctr_encrypt failed: %s", error_to_string(rv));
              }
            }
            else if (self->direction == -1) {
              rv = ctr_decrypt(in_data, out_data, (unsigned long)in_data_len, &self->state);
              if (rv != CRYPT_OK) {
                SvREFCNT_dec(RETVAL);
                croak("FATAL: ctr_decrypt failed: %s", error_to_string(rv));
              }
            }
            else {
              SvREFCNT_dec(RETVAL);
              croak("FATAL: ctr_crypt failed: call start_encrypt or start_decrypt first");
            }
          }
        }
        if (out_len > 0) SvCUR_set(RETVAL, out_len);
    }
    OUTPUT:
        RETVAL

SV *
finish(Crypt::Mode::CTR self)
    CODE:
          self->direction = 0;
          RETVAL = newSVpvn("", 0);
    OUTPUT:
        RETVAL
