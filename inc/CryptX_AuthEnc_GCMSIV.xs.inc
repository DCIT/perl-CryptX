MODULE = CryptX       PACKAGE = Crypt::AuthEnc::GCMSIV

PROTOTYPES: DISABLE

SV *
gcm_siv_encrypt_authenticate(char *cipher_name, SV *key, SV *nonce, SV *aad, SV *plaintext)
    CODE:
    {
        STRLEN k_len = 0, n_len = 0, a_len = 0, pt_len = 0;
        unsigned char *k, *n, *a = NULL, *pt, *ct;
        unsigned long ct_len, tag_len;
        int rv, id;

        id = cryptx_internal_find_cipher(cipher_name);
        if (id == -1) croak("FATAL: find_cipher failed for '%s'", cipher_name);

        if (!SvPOK_spec(key))       croak("FATAL: key must be string/buffer scalar");
        if (!SvPOK_spec(nonce))     croak("FATAL: nonce must be string/buffer scalar");
        if (!SvPOK_spec(plaintext)) croak("FATAL: plaintext must be string/buffer scalar");
        k  = (unsigned char *)SvPVbyte(key,       k_len);
        n  = (unsigned char *)SvPVbyte(nonce,     n_len);
        pt = (unsigned char *)SvPVbyte(plaintext, pt_len);
        if (SvOK(aad)) {
            if (!SvPOK_spec(aad)) croak("FATAL: adata must be string/buffer scalar");
            a = (unsigned char *)SvPVbyte(aad, a_len);
        }

        ct_len = (unsigned long)pt_len + 16;
        RETVAL = NEWSV(0, ct_len);
        SvPOK_only(RETVAL);
        SvCUR_set(RETVAL, ct_len);
        ct = (unsigned char *)SvPVX(RETVAL);
        tag_len = 16;

        rv = gcm_siv_memory(id,
                            k, (unsigned long)k_len,
                            n, (unsigned long)n_len,
                            a, (unsigned long)a_len,
                            pt, (unsigned long)pt_len,
                            ct,                       /* ciphertext output */
                            ct + pt_len, &tag_len,    /* tag appended */
                            LTC_ENCRYPT);
        if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: gcm_siv_memory(encrypt) failed: %s", error_to_string(rv));
        }
    }
    OUTPUT:
        RETVAL

void
gcm_siv_decrypt_verify(char *cipher_name, SV *key, SV *nonce, SV *aad, SV *ciphertext)
    PPCODE:
    {
        STRLEN k_len = 0, n_len = 0, a_len = 0, ct_len = 0;
        unsigned char *k, *n, *a = NULL, *ct, *pt;
        unsigned long pt_len, tag_len;
        int rv, id;
        SV *output;
        unsigned char tag[16];

        id = cryptx_internal_find_cipher(cipher_name);
        if (id == -1) croak("FATAL: find_cipher failed for '%s'", cipher_name);

        if (!SvPOK_spec(key))        croak("FATAL: key must be string/buffer scalar");
        if (!SvPOK_spec(nonce))      croak("FATAL: nonce must be string/buffer scalar");
        if (!SvPOK_spec(ciphertext)) croak("FATAL: ciphertext must be string/buffer scalar");
        k  = (unsigned char *)SvPVbyte(key,        k_len);
        n  = (unsigned char *)SvPVbyte(nonce,      n_len);
        ct = (unsigned char *)SvPVbyte(ciphertext, ct_len);
        if (ct_len < 16) croak("FATAL: ciphertext too short");
        if (SvOK(aad)) {
            if (!SvPOK_spec(aad)) croak("FATAL: adata must be string/buffer scalar");
            a = (unsigned char *)SvPVbyte(aad, a_len);
        }

        pt_len = (unsigned long)ct_len - 16;
        output = NEWSV(0, pt_len > 0 ? pt_len : 1);
        SvPOK_only(output);
        SvCUR_set(output, pt_len);
        pt = (unsigned char *)SvPVX(output);
        memcpy(tag, ct + pt_len, 16);
        tag_len = 16;

        rv = gcm_siv_memory(id,
                            k, (unsigned long)k_len,
                            n, (unsigned long)n_len,
                            a, (unsigned long)a_len,
                            ct, pt_len,           /* ciphertext input */
                            pt,                   /* plaintext output */
                            tag, &tag_len,
                            LTC_DECRYPT);
        if (rv != CRYPT_OK) {
            SvREFCNT_dec(output);
            XPUSHs(sv_2mortal(newSVpvn(NULL, 0))); /* undef */
        } else {
            XPUSHs(sv_2mortal(output));
        }
    }
