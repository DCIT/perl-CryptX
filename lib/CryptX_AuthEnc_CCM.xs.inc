MODULE = CryptX       PACKAGE = Crypt::AuthEnc::CCM

void
_memory_encrypt(char *cipher_name, SV *key, SV *nonce, SV *header, unsigned long tag_len, SV *plaintext)
    PPCODE:
    {
        STRLEN k_len, n_len, h_len, pt_len;
        unsigned char *k, *n, *h, *pt;
        int rv, id;
        unsigned char tag[MAXBLOCKSIZE];
        SV *ct;

        if (!SvPOK(key))       croak("FATAL: key must be string/buffer scalar");
        if (!SvPOK(nonce))     croak("FATAL: nonce must be string/buffer scalar");
        if (!SvPOK(header))    croak("FATAL: header must be string/buffer scalar");
        if (!SvPOK(plaintext)) croak("FATAL: plaintext must be string/buffer scalar");
        k  = (unsigned char *) SvPVbyte(key, k_len);
        n  = (unsigned char *) SvPVbyte(nonce, n_len);
        h  = (unsigned char *) SvPVbyte(header, h_len);
        pt = (unsigned char *) SvPVbyte(plaintext, pt_len);

        id = find_cipher(cipher_name);
        if(id==-1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);

        ct = NEWSV(0, pt_len);
        SvPOK_only(ct);
        SvCUR_set(ct, pt_len);

        if(tag_len<4 || tag_len>16) tag_len = 16;

        rv = ccm_memory(id, k, (unsigned long)k_len, NULL, n, (unsigned long)n_len, h, (unsigned long)h_len,
                        pt, (unsigned long)pt_len, (unsigned char *)SvPV_nolen(ct), tag, &tag_len, CCM_ENCRYPT);
        if (rv != CRYPT_OK) croak("FATAL: ccm_memory failed: %s", error_to_string(rv));

        XPUSHs(sv_2mortal(ct));
        XPUSHs(sv_2mortal(newSVpvn((char*)tag,tag_len)));

        /* int ccm_memory( int cipher,
                           const unsigned char *key,       unsigned long keylen,
                           symmetric_key *uskey,
                           const unsigned char *nonce,     unsigned long noncelen,
                           const unsigned char *header,    unsigned long headerlen,
                           unsigned char *pt,              unsigned long ptlen,
                           unsigned char *ct,
                           unsigned char *tag,             unsigned long *taglen,
                           int direction); */

    }

void
_memory_decrypt(char *cipher_name, SV *key, SV *nonce, SV *header, SV *ciphertext, SV *tag)
    PPCODE:
    {
        STRLEN k_len, n_len, h_len, ct_len, t_len;
        unsigned char *k, *n, *h, *ct, *t;
        int rv, id;
        unsigned char xtag[MAXBLOCKSIZE];
        unsigned long xtag_len;
        SV *pt;

        if (!SvPOK(key))        croak("FATAL: key must be string/buffer scalar");
        if (!SvPOK(nonce))      croak("FATAL: nonce must be string/buffer scalar");
        if (!SvPOK(header))     croak("FATAL: header must be string/buffer scalar");
        if (!SvPOK(ciphertext)) croak("FATAL: ciphertext must be string/buffer scalar");
        if (!SvPOK(tag))        croak("FATAL: tag must be string/buffer scalar");
        k  = (unsigned char *) SvPVbyte(key, k_len);
        n  = (unsigned char *) SvPVbyte(nonce, n_len);
        h  = (unsigned char *) SvPVbyte(header, h_len);
        ct = (unsigned char *) SvPVbyte(ciphertext, ct_len);
        t  = (unsigned char *) SvPVbyte(tag, t_len);

        id = find_cipher(cipher_name);
        if(id==-1) croak("FATAL: find_cipfer failed for '%s'", cipher_name);

        pt = NEWSV(0, ct_len);
        SvPOK_only(pt);
        SvCUR_set(pt, ct_len);

        xtag_len = (unsigned long)t_len;
        Copy(t, xtag, t_len, unsigned char);

        rv = ccm_memory(id, k, (unsigned long)k_len, NULL, n, (unsigned long)n_len, h, (unsigned long)h_len,
                        (unsigned char *)SvPV_nolen(pt), (unsigned long)ct_len, ct, xtag, &xtag_len, CCM_DECRYPT);
        if (rv != CRYPT_OK) {
          XPUSHs(sv_2mortal(newSVpvn(NULL,0))); /* undef */
        }
        else {
          XPUSHs(sv_2mortal(pt));
        }
    }
