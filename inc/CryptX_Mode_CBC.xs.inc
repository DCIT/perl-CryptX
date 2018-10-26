MODULE = CryptX         PACKAGE = Crypt::Mode::CBC

PROTOTYPES: DISABLE

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

Crypt::Mode::CBC
new(Class, char * cipher_name, int padding=1, int rounds=0)
    CODE:
    {
        Newz(0, RETVAL, 1, struct cbc_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        RETVAL->padding_mode = padding;
        RETVAL->padlen = 0;
        RETVAL->direction = 0;
        RETVAL->cipher_rounds = rounds;
        RETVAL->cipher_id = _find_cipher(cipher_name);
        if (RETVAL->cipher_id == -1) {
          Safefree(RETVAL);
          croak("FATAL: find_cipfer failed for '%s'", cipher_name);
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Mode::CBC self)
    CODE:
        Safefree(self);

void
start_decrypt(Crypt::Mode::CBC self, SV * key, SV * iv)
    ALIAS:
        start_encrypt = 1
    PPCODE:
    {
        int rv;
        STRLEN k_len=0;
        unsigned char *k=NULL;
        STRLEN i_len=0;
        unsigned char *i=NULL;

        if (!SvPOK(key))   croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);

        if (!SvPOK(iv))    croak("FATAL: iv must be string/buffer scalar");
        i = (unsigned char *) SvPVbyte(iv, i_len);
        if (i_len != (STRLEN)cipher_descriptor[self->cipher_id].block_length) {
          croak ("FATAL: sizeof(iv) should be equal to blocksize (%d)", cipher_descriptor[self->cipher_id].block_length);
        }
        rv = cbc_start(self->cipher_id, i, k, (unsigned long)k_len, self->cipher_rounds, &self->state);
        if (rv != CRYPT_OK) {
          croak("FATAL: cbc_start failed: %s", error_to_string(rv));
        }

        self->direction = ix == 1 ? 1 : -1;
        self->padlen = 0;
        XPUSHs(ST(0)); /* return self */
    }

SV *
add(Crypt::Mode::CBC self, ...)
    CODE:
    {
        int rv, has_tmp_block, blen, j;
        unsigned long i;
        STRLEN in_data_len, in_data_start, out_len = 0;
        unsigned char *in_data, *out_data, tmp_block[MAXBLOCKSIZE];

        RETVAL = newSVpvn("", 0);
        for (j = 1; j < items; j++) {
          in_data = (unsigned char *)SvPVbyte(ST(j), in_data_len);
          blen = (&self->state)->blocklen;
          in_data_start = 0;
          has_tmp_block = 0;
          if (in_data_len > 0) {
            if (self->direction == 1) {
              /* handle non-empty self->pad buffer */
              if (self->padlen > 0) {
                i = (blen - self->padlen);
                if (in_data_len >= i) { /* enough data to fill pad */
                  Copy(in_data, self->pad+self->padlen, i, unsigned char);
                  in_data_len -= i;
                  in_data_start = i;
                  rv = cbc_encrypt(self->pad, tmp_block, blen, &self->state);
                  if (rv != CRYPT_OK) {
                    SvREFCNT_dec(RETVAL);
                    croak("FATAL: cbc_encrypt failed: %s", error_to_string(rv));
                  }
                  self->padlen = 0;
                  has_tmp_block = 1;
                }
                else { /* not enough data to fill pad */
                  Copy(in_data, self->pad+self->padlen, in_data_len, unsigned char);
                  self->padlen += (int)in_data_len;
                  in_data_len = 0;
                }
              }

              i = (unsigned long)(in_data_len % blen);
              if (in_data_len > 0 && i > 0) { /* save tail of data into pad */
                Copy(in_data + in_data_start + in_data_len - i, self->pad, i, unsigned char);
                self->padlen = i;
                in_data_len -= i;
              }

              if (in_data_len > 0) {
                i = (unsigned long)(has_tmp_block ? in_data_len + blen : in_data_len);
                out_data = (unsigned char*)SvGROW(RETVAL, out_len + i + 1) + out_len;
                out_len += i;
                if (has_tmp_block) {
                  Copy(tmp_block, out_data, blen, unsigned char);
                  out_data += blen;
                }
                rv = cbc_encrypt(in_data+in_data_start, out_data, (unsigned long)in_data_len, &self->state);
                if (rv != CRYPT_OK) {
                  SvREFCNT_dec(RETVAL);
                  croak("FATAL: cbc_encrypt failed: %s", error_to_string(rv));
                }
              } /* in_data_len > 0 */
              else if (has_tmp_block) {
                out_data = (unsigned char*)SvGROW(RETVAL, out_len + blen + 1) + out_len;
                out_len += blen;
                Copy(tmp_block, out_data, blen, unsigned char);
              }
            }
            else if (self->direction == -1) {
              if (self->padlen == blen) {
                rv = cbc_decrypt(self->pad, tmp_block, blen, &self->state);
                if (rv != CRYPT_OK) {
                  SvREFCNT_dec(RETVAL);
                  croak("FATAL: cbc_decrypt failed: %s", error_to_string(rv));
                }
                self->padlen = 0;
                has_tmp_block = 1;
              } /* padlen == blen */
              else if (self->padlen > 0) {
                i = (blen - self->padlen); /* remaining bytes in padding buffer */
                if (in_data_len >= i) { /* enough data to fill pad */
                  Copy(in_data, self->pad+self->padlen, i, unsigned char);
                  self->padlen += i;
                  in_data_len -= i;
                  in_data_start = i;
                  if (in_data_len>0 || self->padding_mode == 0) {
                    rv = cbc_decrypt(self->pad, tmp_block, blen, &self->state);
                    if (rv != CRYPT_OK) {
                      SvREFCNT_dec(RETVAL);
                      croak("FATAL: cbc_decrypt failed: %s", error_to_string(rv));
                    }
                    self->padlen = 0;
                    has_tmp_block = 1;
                  }
                }
                else { /* not enough data to fill pad */
                  Copy(in_data, self->pad+self->padlen, in_data_len, unsigned char);
                  self->padlen += (int)in_data_len;
                  in_data_len = 0;
                }
              } /* padlen > 0 */

              /* here: a/ padlen == 1..16 && in_data_len == 0; b/ padlen == 0 && in_data_len > 0 */
              if (in_data_len>0) {
                i = (unsigned long)(in_data_len % blen);
                if (i>0) { /* save tail of data into pad */
                  Copy(in_data+in_data_start+in_data_len-i, self->pad, i, unsigned char);
                  self->padlen = i;
                  in_data_len -= i;
                }
              }

              if (in_data_len>0) {
                if (self->padlen == 0 && self->padding_mode !=0) {
                  /* in case of padding keep full pad if no more data */
                  Copy(in_data+in_data_start+in_data_len-blen, self->pad, blen, unsigned char);
                  self->padlen = blen;
                  in_data_len -= blen;
                }
                i = (unsigned long)(has_tmp_block ? in_data_len + blen : in_data_len);
                if (i > 0) {
                  out_data = (unsigned char*)SvGROW(RETVAL, out_len + i + 1) + out_len;
                  out_len += i;
                  if (has_tmp_block) {
                    Copy(tmp_block, out_data, blen, unsigned char);
                    out_data += blen;
                  }
                  rv = cbc_decrypt(in_data+in_data_start, out_data, (unsigned long)in_data_len, &self->state);
                  if (rv != CRYPT_OK) {
                    SvREFCNT_dec(RETVAL);
                    croak("FATAL: cbc_decrypt failed: %s", error_to_string(rv));
                  }
                }
              } /* in_data_len>0 */
              else if (has_tmp_block) {
                out_data = (unsigned char*)SvGROW(RETVAL, out_len + blen + 1) + out_len;
                out_len += blen;
                Copy(tmp_block, out_data, blen, unsigned char);
              }
            }
            else {
              SvREFCNT_dec(RETVAL);
              croak("FATAL: call start_decryt or start_encrpyt first (%d)", self->direction);
            }
          }
        }
        if (out_len > 0) SvCUR_set(RETVAL, out_len);
    }
    OUTPUT:
        RETVAL

SV *
finish(Crypt::Mode::CBC self)
    CODE:
    {
        unsigned char tmp_block[MAXBLOCKSIZE];
        int rv;
        unsigned long blen = (&self->state)->blocklen;
        unsigned long padmode;

        if (self->direction == 1) {
          if (self->padlen < 0 || self->padlen >= (int)blen) croak("FATAL: invalid padlen");
          if (self->padding_mode != 0) {
            if      (self->padding_mode == 1) { padmode = LTC_PAD_PKCS7        | (&self->state)->blocklen; }
            else if (self->padding_mode == 2) { padmode = LTC_PAD_ONE_AND_ZERO | (&self->state)->blocklen; }
            else if (self->padding_mode == 3) { padmode = LTC_PAD_ANSI_X923    | (&self->state)->blocklen; }
            else if (self->padding_mode == 4) { padmode = LTC_PAD_ZERO         | (&self->state)->blocklen; }
            else if (self->padding_mode == 5) { padmode = LTC_PAD_ZERO_ALWAYS  | (&self->state)->blocklen; }
            else { croak("FATAL: unknown padding"); }
            blen = sizeof(self->pad);
            rv = padding_pad(self->pad, self->padlen, &blen, padmode);
            if (rv != CRYPT_OK) croak("FATAL: padding_pad failed: %s", error_to_string(rv));
            rv = cbc_encrypt(self->pad, tmp_block, blen, &self->state);
            if (rv != CRYPT_OK) croak("FATAL: cbc_encrypt failed: %s", error_to_string(rv));
          }
          else {
            if (self->padlen > 0) croak("FATAL: cbc_encrypt, input data length not multiple of %d", (int)blen);
            blen = 0;
          }
        }
        else if (self->direction == -1) {
          if (self->padlen > 0) {
            if (self->padlen != (int)blen) croak("FATAL: cipher text length has to be multiple of %d (%d)", (int)blen, self->padlen);
            rv = cbc_decrypt(self->pad, tmp_block, blen, &self->state);
            if (rv != CRYPT_OK) croak("FATAL: cbc_decrypt failed: %s", error_to_string(rv));
            if (self->padding_mode != 0) {
              if      (self->padding_mode == 1) { padmode = LTC_PAD_PKCS7        | (&self->state)->blocklen; }
              else if (self->padding_mode == 2) { padmode = LTC_PAD_ONE_AND_ZERO | (&self->state)->blocklen; }
              else if (self->padding_mode == 3) { padmode = LTC_PAD_ANSI_X923    | (&self->state)->blocklen; }
              else if (self->padding_mode == 4) { padmode = LTC_PAD_ZERO         | (&self->state)->blocklen; }
              else if (self->padding_mode == 5) { padmode = LTC_PAD_ZERO_ALWAYS  | (&self->state)->blocklen; }
              else { croak("FATAL: unknown padding"); }
              rv = padding_depad(tmp_block, &blen, padmode);
              if (rv != CRYPT_OK) croak("FATAL: padding_depad failed: %s", error_to_string(rv));
            }
            else {
              /* "no padding" == there is no need to do anything */
            }
          }
          else {
            blen = 0;
          }
        }
        else {
           croak("FATAL: invalid direction");
        }

        self->direction = 0;
        RETVAL = newSVpvn((char*)tmp_block, blen);
    }
    OUTPUT:
        RETVAL
