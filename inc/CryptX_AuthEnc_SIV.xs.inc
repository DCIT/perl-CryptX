MODULE = CryptX       PACKAGE = Crypt::AuthEnc::SIV

PROTOTYPES: DISABLE

SV *
siv_encrypt_authenticate(char *cipher_name, SV *key, SV *plaintext, SV *aad = &PL_sv_undef)
    CODE:
    {
        STRLEN k_len = 0, pt_len = 0;
        unsigned char *k, *pt, *ct;
        unsigned long ct_len;
        int rv, id;
        const unsigned char *ad_ptrs[126];
        unsigned long        ad_lens[126];
        unsigned long n_ad = 0;
        STRLEN tmp;

        id = cryptx_internal_find_cipher(cipher_name);
        if (id == -1) croak("FATAL: find_cipher failed for '%s'", cipher_name);

        k  = (unsigned char *)SvPVbyte(key, k_len);
        pt = (unsigned char *)SvPVbyte(plaintext, pt_len);

        if (SvOK(aad)) {
            if (SvROK(aad) && SvTYPE(SvRV(aad)) == SVt_PVAV) {
                AV *av = (AV *)SvRV(aad);
                SSize_t i, alen = av_len(av);
                for (i = 0; i <= alen; i++) {
                    SV **svp = av_fetch(av, i, 0);
                    if (svp && SvOK(*svp)) {
                        if (n_ad >= 126) croak("FATAL: too many associated data components (max 126)");
                        ad_ptrs[n_ad] = (const unsigned char *)SvPVbyte(*svp, tmp);
                        ad_lens[n_ad] = (unsigned long)tmp;
                        n_ad++;
                    }
                }
            } else if (SvPOK(aad)) {
                ad_ptrs[0] = (const unsigned char *)SvPVbyte(aad, tmp);
                ad_lens[0] = (unsigned long)tmp;
                n_ad = 1;
            }
        }
        ct_len = (unsigned long)pt_len + 16;
        RETVAL = NEWSV(0, ct_len > 0 ? ct_len : 1);
        SvPOK_only(RETVAL);
        SvCUR_set(RETVAL, ct_len);
        ct = (unsigned char *)SvPVX(RETVAL);

        rv = siv_encrypt_memory(id, k, (unsigned long)k_len,
                                n_ad,
                                ad_ptrs, ad_lens,
                                pt, (unsigned long)pt_len,
                                ct, &ct_len);
        if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: siv_encrypt_memory failed: %s", error_to_string(rv));
        }
        SvCUR_set(RETVAL, ct_len);
    }
    OUTPUT:
        RETVAL

void
siv_decrypt_verify(char *cipher_name, SV *key, SV *ciphertext, SV *aad = &PL_sv_undef)
    PPCODE:
    {
        STRLEN k_len = 0, ct_len = 0;
        unsigned char *k, *ct, *pt;
        unsigned long pt_len;
        int rv, id;
        SV *output;
        const unsigned char *ad_ptrs[126];
        unsigned long        ad_lens[126];
        unsigned long n_ad = 0;
        STRLEN tmp;

        id = cryptx_internal_find_cipher(cipher_name);
        if (id == -1) croak("FATAL: find_cipher failed for '%s'", cipher_name);

        k  = (unsigned char *)SvPVbyte(key, k_len);
        ct = (unsigned char *)SvPVbyte(ciphertext, ct_len);
        if (ct_len < 16) croak("FATAL: ciphertext too short");

        if (SvOK(aad)) {
            if (SvROK(aad) && SvTYPE(SvRV(aad)) == SVt_PVAV) {
                AV *av = (AV *)SvRV(aad);
                SSize_t i, alen = av_len(av);
                for (i = 0; i <= alen; i++) {
                    SV **svp = av_fetch(av, i, 0);
                    if (svp && SvOK(*svp)) {
                        if (n_ad >= 126) croak("FATAL: too many associated data components (max 126)");
                        ad_ptrs[n_ad] = (const unsigned char *)SvPVbyte(*svp, tmp);
                        ad_lens[n_ad] = (unsigned long)tmp;
                        n_ad++;
                    }
                }
            } else if (SvPOK(aad)) {
                ad_ptrs[0] = (const unsigned char *)SvPVbyte(aad, tmp);
                ad_lens[0] = (unsigned long)tmp;
                n_ad = 1;
            }
        }
        pt_len = (unsigned long)ct_len - 16;
        output = NEWSV(0, pt_len > 0 ? pt_len : 1);
        SvPOK_only(output);
        SvCUR_set(output, pt_len);
        pt = (unsigned char *)SvPVX(output);

        rv = siv_decrypt_memory(id, k, (unsigned long)k_len,
                                n_ad,
                                ad_ptrs, ad_lens,
                                ct, (unsigned long)ct_len,
                                pt, &pt_len);
        if (rv != CRYPT_OK) {
            SvREFCNT_dec(output);
            XPUSHs(sv_2mortal(newSVpvn(NULL, 0))); /* undef */
        } else {
            SvCUR_set(output, pt_len);
            XPUSHs(sv_2mortal(output));
        }
    }
