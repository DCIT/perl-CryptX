MODULE = CryptX         PACKAGE = Crypt::Mode::XTS

PROTOTYPES: DISABLE

### hand-written XS - unlike other Crypt::Mode::* this file is NOT generated from _generators/Mode.xs.inc.tt

Crypt::Mode::XTS
new(Class, SV * cipher, SV * key, int rounds=0)
    CODE:
    {
        int rv, id, half_ks;
        STRLEN k_len = 0, half = 0;
        unsigned char *k = NULL;
        char *cipher_name;

        if (!SvPOK_spec(cipher)) croak("FATAL: cipher name must be string scalar");
        cipher_name = SvPVbyte_nolen(cipher);
        if (!SvPOK_spec(key))    croak("FATAL: key must be string/buffer scalar");
        k = (unsigned char *) SvPVbyte(key, k_len);

        id = cryptx_internal_find_cipher(cipher_name);
        if (id == -1) {
          if (k_len > 0 && k_len < 100 && memchr(k, 0, k_len) == NULL && cryptx_internal_find_cipher((const char *)k) != -1) {
            croak("FATAL: find_cipher failed for '%s' (did you mean new(cipher, key)?)", cipher_name);
          }
          croak("FATAL: find_cipher failed for '%s'", cipher_name);
        }
        if (cipher_descriptor[id].block_length != 16) {
          croak("FATAL: XTS requires a 128-bit block cipher");
        }

        if (k_len == 0 || k_len % 2 != 0) {
          croak("FATAL: XTS key must be key1 || key2, two equal-length '%s' keys (got %d bytes)", cipher_name, (int)k_len);
        }
        half = k_len / 2;
        half_ks = (int)half;
        if (cipher_descriptor[id].keysize(&half_ks) != CRYPT_OK || half_ks != (int)half) {
          croak("FATAL: XTS key must be key1 || key2, two equal-length '%s' keys (%d is not a valid key size)", cipher_name, (int)half);
        }
        if (mem_neq(k, k + half, half) == 0) {
          croak("FATAL: XTS requires key1 != key2 (FIPS 140 IG A.9)");
        }

        Newz(0, RETVAL, 1, struct xts_struct);
        if (!RETVAL) croak("FATAL: Newz failed");
        rv = xts_start(id, k, k + half, (unsigned long)half, rounds, &RETVAL->state);
        if (rv != CRYPT_OK) {
          Safefree(RETVAL);
          croak("FATAL: xts_start failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::Mode::XTS self)
    CODE:
    {
        xts_done(&self->state);
        zeromem(&self->state, sizeof(symmetric_xts));
        Safefree(self);
    }

SV *
encrypt(Crypt::Mode::XTS self, SV * data, SV * tweak)
    ALIAS:
        decrypt = 1
    CODE:
    {
        int rv;
        STRLEN in_len = 0, t_len = 0;
        unsigned char *in_data, *out_data, *t_raw;
        unsigned char t[16];

        if (!SvPOK_spec(tweak)) croak("FATAL: tweak must be a 16-byte string or a non-negative integer < 2^64");
        t_raw = (unsigned char *) SvPVbyte(tweak, t_len);
        if (t_len == 16) {
          Copy(t_raw, t, 16, unsigned char);
        }
        else {
          /* data unit sequence number: 64-bit little-endian, zero-padded to 16 bytes */
          UV unit = 0;
          int i, flags;
          flags = grok_number((const char *)t_raw, t_len, &unit);
          if (!(flags & IS_NUMBER_IN_UV) || (flags & (IS_NUMBER_NEG|IS_NUMBER_NOT_INT))) {
            croak("FATAL: tweak must be a 16-byte string or a non-negative integer < 2^64");
          }
          for (i = 0; i < 16; i++) {
            t[i] = (unsigned char)(unit & 0xFF);
            unit >>= 8;
          }
        }

        if (!SvPOK_spec(data)) croak("FATAL: data must be string/buffer scalar");
        in_data = (unsigned char *) SvPVbyte(data, in_len);
        if (in_len < 16)       croak("FATAL: XTS data unit must be at least 16 bytes (one full block)");
        if (in_len > 16777216) croak("FATAL: XTS data unit must not exceed 2^20 blocks / 16MiB (NIST SP 800-38E)");

        RETVAL = newSVpvn("", 0);
        out_data = (unsigned char *) SvGROW(RETVAL, in_len + 1);
        if (ix == 1) {
          rv = xts_decrypt(in_data, (unsigned long)in_len, out_data, t, &self->state);
        }
        else {
          rv = xts_encrypt(in_data, (unsigned long)in_len, out_data, t, &self->state);
        }
        if (rv != CRYPT_OK) {
          SvREFCNT_dec(RETVAL);
          croak("FATAL: xts_%scrypt failed: %s", ix == 1 ? "de" : "en", error_to_string(rv));
        }
        SvCUR_set(RETVAL, in_len);
        *SvEND(RETVAL) = '\0';
    }
    OUTPUT:
        RETVAL
