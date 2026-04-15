MODULE = CryptX         PACKAGE = Crypt::KeyDerivation

PROTOTYPES: DISABLE

SV *
pbkdf1(SV * password, SV * salt, int iteration_count = 5000, const char * hash_name = "SHA256", unsigned long output_len = 32)
    CODE:
    {
        int rv, id;
        unsigned char *output;
        unsigned char *password_ptr=NULL;
        STRLEN password_len=0;
        unsigned char *salt_ptr=NULL;
        STRLEN salt_len=0;

        if (output_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          id = cryptx_internal_find_hash(hash_name);
          if (id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);

          password_ptr = (unsigned char *)SvPVbyte(password, password_len);
          salt_ptr = (unsigned char *)SvPVbyte(salt, salt_len);
          if (salt_len < 8) croak("FATAL: salt_len has to be 8");

          RETVAL = NEWSV(0, output_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, output_len);
          output = (unsigned char *)SvPVX(RETVAL);

          rv = pkcs_5_alg1(password_ptr, (unsigned long)password_len, salt_ptr, iteration_count, id, output, &output_len);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: pkcs_5_alg1 process failed: %s", error_to_string(rv));
          }
          SvCUR_set(RETVAL, output_len);
        }
    }
    OUTPUT:
        RETVAL

SV *
pbkdf2(SV * password, SV * salt, int iteration_count = 5000, const char * hash_name = "SHA256", unsigned long output_len = 32)
    CODE:
    {
        int rv, id;
        unsigned char *output;
        unsigned char *password_ptr=NULL;
        STRLEN password_len=0;
        unsigned char *salt_ptr=NULL;
        STRLEN salt_len=0;

        if (output_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          id = cryptx_internal_find_hash(hash_name);
          if (id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);

          password_ptr = (unsigned char *)SvPVbyte(password, password_len);
          salt_ptr = (unsigned char *)SvPVbyte(salt, salt_len);

          RETVAL = NEWSV(0, output_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, output_len);
          output = (unsigned char *)SvPVX(RETVAL);

          rv = pkcs_5_alg2(password_ptr, (unsigned long)password_len, salt_ptr, (unsigned long)salt_len, iteration_count, id, output, &output_len);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: pkcs_5_alg2 process failed: %s", error_to_string(rv));
          }
          SvCUR_set(RETVAL, output_len);
        }
    }
    OUTPUT:
        RETVAL

SV *
hkdf_extract(SV * in, SV * salt = &PL_sv_undef, const char * hash_name = "SHA256")
    CODE:
    {
        int rv, id;
        unsigned char output[MAXBLOCKSIZE];
        unsigned long output_len;
        unsigned char *in_ptr = NULL, *salt_ptr = NULL;
        STRLEN in_len = 0, salt_len = 0;

        id = cryptx_internal_find_hash(hash_name);
        if (id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);

        if (SvPOK(in))   in_ptr = (unsigned char *)SvPVbyte(in, in_len);
        if (SvPOK(salt)) salt_ptr = (unsigned char *)SvPVbyte(salt, salt_len);

        output_len = sizeof(output);
        rv = hkdf_extract(id, salt_ptr, (unsigned long)salt_len, in_ptr, (unsigned long)in_len, output, &output_len);
        if (rv != CRYPT_OK) croak("FATAL: hkdf_extract process failed: %s", error_to_string(rv));

        RETVAL = newSVpvn((char *)output, output_len);
    }
    OUTPUT:
        RETVAL

SV *
hkdf_expand(SV * in, const char * hash_name = "SHA256", unsigned long output_len = 32, SV * info = &PL_sv_undef)
    CODE:
    {
        int rv, id;
        unsigned char *output;
        unsigned char *in_ptr = NULL, *info_ptr = NULL;
        STRLEN in_len = 0, info_len = 0;

        if (output_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          id = cryptx_internal_find_hash(hash_name);
          if (id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);

          if (SvPOK(in))   in_ptr = (unsigned char *)SvPVbyte(in, in_len);
          if (SvPOK(info)) info_ptr = (unsigned char *)SvPVbyte(info, info_len);

          RETVAL = NEWSV(0, output_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, output_len);
          output = (unsigned char *)SvPVX(RETVAL);

          rv = hkdf_expand(id, info_ptr, (unsigned long)info_len, in_ptr, (unsigned long)in_len, output, output_len);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: hkdf_expand process failed: %s", error_to_string(rv));
          }
          SvCUR_set(RETVAL, output_len);
        }
    }
    OUTPUT:
        RETVAL

SV *
hkdf(SV * in, SV * salt, const char * hash_name = "SHA256", unsigned long output_len = 32, SV * info = &PL_sv_undef)
    CODE:
    {
        int rv, id;
        unsigned char *output;
        unsigned char *in_ptr = NULL, *info_ptr = NULL, *salt_ptr = NULL;
        STRLEN in_len = 0, info_len = 0, salt_len = 0;

        if (output_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          id = cryptx_internal_find_hash(hash_name);
          if (id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);

          if (SvPOK(in))   in_ptr   = (unsigned char *)SvPVbyte(in, in_len);
          if (SvPOK(info)) info_ptr = (unsigned char *)SvPVbyte(info, info_len);
          if (SvPOK(salt)) salt_ptr = (unsigned char *)SvPVbyte(salt, salt_len);

          RETVAL = NEWSV(0, output_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, output_len);
          output = (unsigned char *)SvPVX(RETVAL);

          rv = hkdf(id, salt_ptr, (unsigned long)salt_len, info_ptr, (unsigned long)info_len, in_ptr, (unsigned long)in_len, output, output_len);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: hkdf_expand process failed: %s", error_to_string(rv));
          }
          SvCUR_set(RETVAL, output_len);
        }
    }
    OUTPUT:
        RETVAL

SV *
bcrypt_pbkdf(SV * password, SV * salt, unsigned int rounds = 16, const char * hash_name = "SHA512", unsigned long output_len = 32)
    CODE:
    {
        int rv, id;
        unsigned char *output;
        unsigned char *password_ptr=NULL;
        STRLEN password_len=0;
        unsigned char *salt_ptr=NULL;
        STRLEN salt_len=0;

        if (output_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          id = cryptx_internal_find_hash(hash_name);
          if (id == -1) croak("FATAL: find_hash failed for '%s'", hash_name);

          password_ptr = (unsigned char *)SvPVbyte(password, password_len);
          salt_ptr     = (unsigned char *)SvPVbyte(salt, salt_len);

          RETVAL = NEWSV(0, output_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, output_len);
          output = (unsigned char *)SvPVX(RETVAL);

          rv = bcrypt_pbkdf_openbsd(password_ptr, (unsigned long)password_len, salt_ptr, (unsigned long)salt_len, rounds, id, output, &output_len);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: bcrypt_pbkdf process failed: %s", error_to_string(rv));
          }
          SvCUR_set(RETVAL, output_len);
        }
    }
    OUTPUT:
        RETVAL

SV *
scrypt_pbkdf(SV * password, SV * salt, unsigned long N = 1024, unsigned long r = 8, unsigned long p = 1, unsigned long output_len = 32)
    CODE:
    {
        int rv;
        unsigned char *output;
        unsigned char *password_ptr=NULL;
        STRLEN password_len=0;
        unsigned char *salt_ptr=NULL;
        STRLEN salt_len=0;

        if (output_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          password_ptr = (unsigned char *)SvPVbyte(password, password_len);
          salt_ptr     = (unsigned char *)SvPVbyte(salt, salt_len);

          RETVAL = NEWSV(0, output_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, output_len);
          output = (unsigned char *)SvPVX(RETVAL);

          rv = scrypt_pbkdf(password_ptr, (unsigned long)password_len, salt_ptr, (unsigned long)salt_len, N, r, p, output, output_len);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: scrypt_pbkdf process failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL

SV *
argon2_pbkdf(const char * type, SV * password, SV * salt, unsigned int t_cost = 3, unsigned int m_factor = 65536, unsigned int parallelism = 1, unsigned long output_len = 32, SV * secret = &PL_sv_undef, SV * ad = &PL_sv_undef)
    CODE:
    {
        int rv;
        argon2_type argon2_t;
        unsigned char *output;
        unsigned char *password_ptr=NULL, *salt_ptr=NULL, *secret_ptr=NULL, *ad_ptr=NULL;
        STRLEN password_len=0, salt_len=0, secret_len=0, ad_len=0;

        if (output_len == 0) {
          RETVAL = newSVpvn("", 0);
        }
        else {
          if      (strcmp(type, "argon2d")  == 0) argon2_t = ARGON2_D;
          else if (strcmp(type, "argon2i")  == 0) argon2_t = ARGON2_I;
          else if (strcmp(type, "argon2id") == 0) argon2_t = ARGON2_ID;
          else croak("FATAL: unknown argon2 type '%s'", type);

          password_ptr = (unsigned char *)SvPVbyte(password, password_len);
          salt_ptr     = (unsigned char *)SvPVbyte(salt, salt_len);
          if (SvPOK(secret)) secret_ptr = (unsigned char *)SvPVbyte(secret, secret_len);
          if (SvPOK(ad))     ad_ptr     = (unsigned char *)SvPVbyte(ad, ad_len);

          RETVAL = NEWSV(0, output_len); /* avoid zero! */
          SvPOK_only(RETVAL);
          SvCUR_set(RETVAL, output_len);
          output = (unsigned char *)SvPVX(RETVAL);

          rv = argon2_hash(password_ptr, (unsigned long)password_len,
                           salt_ptr,     (unsigned long)salt_len,
                           secret_ptr,   (unsigned long)secret_len,
                           ad_ptr,       (unsigned long)ad_len,
                           t_cost, m_factor, parallelism, argon2_t,
                           output, output_len);
          if (rv != CRYPT_OK) {
            SvREFCNT_dec(RETVAL);
            croak("FATAL: argon2_pbkdf failed: %s", error_to_string(rv));
          }
        }
    }
    OUTPUT:
        RETVAL
