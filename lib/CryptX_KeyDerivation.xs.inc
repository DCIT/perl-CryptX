MODULE = CryptX         PACKAGE = Crypt::KeyDerivation

SV *
_pkcs_5_alg1(SV * password, SV * salt, int iteration_count, char * hash_name, int len)
    CODE:
    {
        /*
        int pkcs_5_alg1(const unsigned char *password, unsigned long password_len, 
                        const unsigned char *salt, 
                        int iteration_count,  int hash_idx,
                        unsigned char *out,   unsigned long *outlen)
        */
        int rv, id;
        unsigned long output_len;
        unsigned char *output;
        unsigned char *password_ptr=NULL;
        STRLEN password_len=0;
        unsigned char *salt_ptr=NULL;
        STRLEN salt_len=0;

        id = find_hash(hash_name);
        if(id==-1) croak("FATAL: find_hash failed for '%s'", hash_name);
        
        password_ptr = (unsigned char *)SvPVbyte(password, password_len);
        salt_ptr = (unsigned char *)SvPVbyte(salt, salt_len);
        if (salt_len < 8) croak("FATAL: salt_len has to be 8");
        
        output_len = len;
        Newz(0, output, output_len, unsigned char);
        if (!output) croak("FATAL: Newz failed [%ld]", output_len);
        
        rv = pkcs_5_alg1(password_ptr, password_len, salt_ptr, iteration_count, id, output, &output_len);
        if (rv != CRYPT_OK) croak("FATAL: pkcs_5_alg1 process failed: %s", error_to_string(rv));
        
        RETVAL = newSVpvn((char *)output, output_len);
        Safefree(output);
    }
    OUTPUT:
        RETVAL

SV *
_pkcs_5_alg2(SV * password, SV * salt, int iteration_count, char * hash_name, int len)
    CODE:
    {
        /*
        int pkcs_5_alg2(const unsigned char *password, unsigned long password_len, 
                        const unsigned char *salt,     unsigned long salt_len,
                        int iteration_count,           int hash_idx,
                        unsigned char *out,            unsigned long *outlen)
        */
        int rv, id;
        unsigned long output_len;
        unsigned char *output;
        unsigned char *password_ptr=NULL;
        STRLEN password_len=0;
        unsigned char *salt_ptr=NULL;
        STRLEN salt_len=0;

        id = find_hash(hash_name);
        if(id==-1) croak("FATAL: find_hash failed for '%s'", hash_name);
        
        password_ptr = (unsigned char *)SvPVbyte(password, password_len);
        salt_ptr = (unsigned char *)SvPVbyte(salt, salt_len);
        
        output_len = len;
        Newz(0, output, output_len, unsigned char);
        if (!output) croak("FATAL: Newz failed [%ld]", output_len);
        
        rv = pkcs_5_alg2(password_ptr, password_len, salt_ptr, salt_len, iteration_count, id, output, &output_len);
        if (rv != CRYPT_OK) croak("FATAL: pkcs_5_alg2 process failed: %s", error_to_string(rv));
        
        RETVAL = newSVpvn((char *)output, output_len);
        Safefree(output);
    }
    OUTPUT:
        RETVAL

SV *
_hkdf_extract(char * hash_name, SV * salt, SV * in)
    CODE:
    {
        /*
        int hkdf_extract(int hash_idx, const unsigned char *salt, unsigned long  saltlen,
                                       const unsigned char *in,   unsigned long  inlen,
                                       unsigned char *out,  unsigned long *outlen)
        */
        int rv, id;
        unsigned char output[MAXBLOCKSIZE];
        unsigned long output_len;
        unsigned char *in_ptr=NULL;
        STRLEN in_len=0;
        unsigned char *salt_ptr=NULL;
        STRLEN salt_len=0;

        id = find_hash(hash_name);
        if(id==-1) croak("FATAL: find_hash failed for '%s'", hash_name);
        
        in_ptr = (unsigned char *)SvPVbyte(in, in_len);
        salt_ptr = (unsigned char *)SvPVbyte(salt, salt_len);
        
        output_len = sizeof(output);
        rv = hkdf_extract(id, salt_ptr, salt_len, in_ptr, in_len, output, &output_len);
        if (rv != CRYPT_OK) croak("FATAL: hkdf_extract process failed: %s", error_to_string(rv));
        
        RETVAL = newSVpvn((char *)output, output_len);
    }
    OUTPUT:
        RETVAL

SV *
_hkdf_expand(char * hash_name, SV * info, SV * in, unsigned long output_len)
    CODE:
    {
        /*
        int hkdf_expand(int hash_idx, const unsigned char *info, unsigned long infolen,
                                      const unsigned char *in,   unsigned long inlen,
                                      unsigned char *out,  unsigned long outlen)
        */
        int rv, id;
        unsigned char *output;
        unsigned char *in_ptr=NULL;
        STRLEN in_len=0;
        unsigned char *info_ptr=NULL;
        STRLEN info_len=0;

        id = find_hash(hash_name);
        if(id==-1) croak("FATAL: find_hash failed for '%s'", hash_name);
        
        in_ptr = (unsigned char *)SvPVbyte(in, in_len);
        info_ptr = (unsigned char *)SvPVbyte(info, info_len);
        
        Newz(0, output, output_len, unsigned char);
        if (!output) croak("FATAL: Newz failed [%ld]", output_len);
        
        rv = hkdf_expand(id, info_ptr, info_len, in_ptr, in_len, output, output_len);
        if (rv != CRYPT_OK) croak("FATAL: hkdf_expand process failed: %s", error_to_string(rv));
        
        RETVAL = newSVpvn((char *)output, output_len);
        Safefree(output);
    }
    OUTPUT:
        RETVAL

SV *
_hkdf(char * hash_name, SV * salt, SV * info, SV * in, unsigned long output_len)
    CODE:
    {
        /*
        int hkdf(int hash_idx, const unsigned char *salt, unsigned long saltlen,
                               const unsigned char *info, unsigned long infolen,
                               const unsigned char *in,   unsigned long inlen,
                               unsigned char *out,  unsigned long outlen)
        */
        int rv, id;
        unsigned char *output;
        unsigned char *in_ptr=NULL;
        STRLEN in_len=0;
        unsigned char *info_ptr=NULL;
        STRLEN info_len=0;
        unsigned char *salt_ptr=NULL;
        STRLEN salt_len=0;

        id = find_hash(hash_name);
        if(id==-1) croak("FATAL: find_hash failed for '%s'", hash_name);
        
        in_ptr = (unsigned char *)SvPVbyte(in, in_len);
        info_ptr = (unsigned char *)SvPVbyte(info, info_len);
        salt_ptr = (unsigned char *)SvPVbyte(salt, salt_len);
        
        Newz(0, output, output_len, unsigned char);
        if (!output) croak("FATAL: Newz failed [%ld]", output_len);
        
        rv = hkdf(id, salt_ptr, salt_len, info_ptr, info_len, in_ptr, in_len, output, output_len);
        if (rv != CRYPT_OK) croak("FATAL: hkdf_expand process failed: %s", error_to_string(rv));
        
        RETVAL = newSVpvn((char *)output, output_len);
        Safefree(output);
    }
    OUTPUT:
        RETVAL

