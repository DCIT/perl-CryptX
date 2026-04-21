MODULE = CryptX         PACKAGE = Crypt::ASN1

PROTOTYPES: DISABLE

SV *
asn1_decode_der(SV *der, SV *opts = &PL_sv_undef)
    CODE:
    {
        STRLEN der_len = 0;
        unsigned char *der_ptr = (unsigned char *)SvPVbyte(der, der_len);
        unsigned long  inlen   = (unsigned long)der_len;
        ltc_asn1_list *list    = NULL;
        int rv;
        asn1_opts_t o = { 0, 0, 0, NULL };

        if (SvROK(opts) && SvTYPE(SvRV(opts)) == SVt_PVHV) {
            HV *h = (HV *)SvRV(opts);
            SV **sv;
            if ((sv = hv_fetchs(h, "int", 0)) && SvOK(*sv)) {
                const char *v = SvPV_nolen(*sv);
                if      (strEQ(v, "hex"))   o.int_fmt = 1;
                else if (strEQ(v, "bytes")) o.int_fmt = 2;
            }
            if ((sv = hv_fetchs(h, "bin", 0)) && SvOK(*sv)) {
                const char *v = SvPV_nolen(*sv);
                if      (strEQ(v, "hex"))    o.bin_fmt = 1;
                else if (strEQ(v, "base64")) o.bin_fmt = 2;
            }
            if ((sv = hv_fetchs(h, "dt", 0)) && SvOK(*sv)) {
                const char *v = SvPV_nolen(*sv);
                if (strEQ(v, "epoch")) o.dt_fmt = 1;
            }
            if ((sv = hv_fetchs(h, "oidmap", 0)) && SvROK(*sv) && SvTYPE(SvRV(*sv)) == SVt_PVHV) {
                o.oidmap = (HV *)SvRV(*sv);
            }
        }

        rv = der_decode_sequence_flexi(der_ptr, &inlen, &list);
        if (rv != CRYPT_OK) croak("FATAL: asn1_decode_der failed: %s", error_to_string(rv));

        RETVAL = newRV_noinc(s_ltc_asn1_to_perl(aTHX_ list, o));
        der_sequence_free(list);
    }
    OUTPUT:
        RETVAL
