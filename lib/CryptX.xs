#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#undef LTC_SOURCE
#include "tomcrypt.h"

typedef struct cipher_struct {          /* used by Crypt::Cipher */
  symmetric_key skey;
  int id;
  struct ltc_cipher_descriptor *desc;
} *Crypt__Cipher;

typedef struct digest_struct {          /* used by Crypt::Digest */
  hash_state state;
  int id;
  struct ltc_hash_descriptor *desc;
} *Crypt__Digest;

typedef struct f9_struct {              /* used by Crypt::Mac::F9 */
  f9_state state;
  int id;
} *Crypt__Mac__F9;

typedef struct hmac_struct {            /* used by Crypt::Mac::HMAC */
  hmac_state state;
  int id;
} *Crypt__Mac__HMAC;

typedef struct omac_struct {            /* used by Crypt::Mac::OMAC */
  omac_state state;
  int id;
} *Crypt__Mac__OMAC;

typedef struct pelican_struct {         /* used by Crypt::Mac::Pelican */
  pelican_state state;
  int id;
} *Crypt__Mac__Pelican;

typedef struct pmac_struct {            /* used by Crypt::Mac::PMAC */
  pmac_state state;
  int id;
} *Crypt__Mac__PMAC;

typedef struct xcbc_struct {            /* used by Crypt::Mac::XCBC */
  xcbc_state state;
  int id;
} *Crypt__Mac__XCBC;

MODULE = CryptX       PACKAGE = CryptX      PREFIX = CryptX_

BOOT:
    if(register_cipher(&blowfish_desc)==-1)    { croak("FATAL: cannot register_cipher blowfish"); }
    if(register_cipher(&rc5_desc)==-1)         { croak("FATAL: cannot register_cipher rc5"); }
    if(register_cipher(&rc6_desc)==-1)         { croak("FATAL: cannot register_cipher rc6"); }
    if(register_cipher(&rc2_desc)==-1)         { croak("FATAL: cannot register_cipher rc2"); }
    if(register_cipher(&saferp_desc)==-1)      { croak("FATAL: cannot register_cipher saferp"); }
    if(register_cipher(&safer_k64_desc)==-1)   { croak("FATAL: cannot register_cipher safer_k64"); }
    if(register_cipher(&safer_k128_desc)==-1)  { croak("FATAL: cannot register_cipher safer_k128"); }
    if(register_cipher(&safer_sk64_desc)==-1)  { croak("FATAL: cannot register_cipher safer_sk64"); }
    if(register_cipher(&safer_sk128_desc)==-1) { croak("FATAL: cannot register_cipher safer_sk128"); }
    if(register_cipher(&aes_desc)==-1)         { croak("FATAL: cannot register_cipher aes"); }
    if(register_cipher(&xtea_desc)==-1)        { croak("FATAL: cannot register_cipher xtea"); }
    if(register_cipher(&twofish_desc)==-1)     { croak("FATAL: cannot register_cipher twofish"); }
    if(register_cipher(&des_desc)==-1)         { croak("FATAL: cannot register_cipher des"); }
    if(register_cipher(&des3_desc)==-1)        { croak("FATAL: cannot register_cipher des3"); }
    if(register_cipher(&cast5_desc)==-1)       { croak("FATAL: cannot register_cipher cast5"); }
    if(register_cipher(&noekeon_desc)==-1)     { croak("FATAL: cannot register_cipher noekeon"); }
    if(register_cipher(&skipjack_desc)==-1)    { croak("FATAL: cannot register_cipher skipjack"); }
    if(register_cipher(&khazad_desc)==-1)      { croak("FATAL: cannot register_cipher khazad"); }
    if(register_cipher(&anubis_desc)==-1)      { croak("FATAL: cannot register_cipher anubis"); }
    if(register_cipher(&kseed_desc)==-1)       { croak("FATAL: cannot register_cipher kseed"); }
    if(register_cipher(&kasumi_desc)==-1)      { croak("FATAL: cannot register_cipher kasumi"); }
    if(register_cipher(&multi2_desc)==-1)      { croak("FATAL: cannot register_cipher multi2"); }
    if(register_cipher(&camellia_desc)==-1)    { croak("FATAL: cannot register_cipher camellia"); }
    /* --- */
    if(register_hash(&chc_desc)==-1)           { croak("FATAL: cannot register_hash chc_hash"); }
    if(register_hash(&md2_desc)==-1)           { croak("FATAL: cannot register_hash md2"); }
    if(register_hash(&md4_desc)==-1)           { croak("FATAL: cannot register_hash md4"); }
    if(register_hash(&md5_desc)==-1)           { croak("FATAL: cannot register_hash md5"); }
    if(register_hash(&rmd128_desc)==-1)        { croak("FATAL: cannot register_hash rmd128"); }
    if(register_hash(&rmd160_desc)==-1)        { croak("FATAL: cannot register_hash rmd160"); }
    if(register_hash(&rmd256_desc)==-1)        { croak("FATAL: cannot register_hash rmd256"); }
    if(register_hash(&rmd320_desc)==-1)        { croak("FATAL: cannot register_hash rmd320"); }
    if(register_hash(&sha1_desc)==-1)          { croak("FATAL: cannot register_hash sha1"); }
    if(register_hash(&sha224_desc)==-1)        { croak("FATAL: cannot register_hash sha224"); }
    if(register_hash(&sha256_desc)==-1)        { croak("FATAL: cannot register_hash sha256"); }
    if(register_hash(&sha384_desc)==-1)        { croak("FATAL: cannot register_hash sha384"); }
    if(register_hash(&sha512_desc)==-1)        { croak("FATAL: cannot register_hash sha512"); }
    if(register_hash(&tiger_desc)==-1)         { croak("FATAL: cannot register_hash tiger"); }
    if(register_hash(&whirlpool_desc)==-1)     { croak("FATAL: cannot register_hash whirlpool"); }    
    /* --- */
    if(chc_register(find_cipher("aes"))==-1)   { croak("FATAL: chc_register failed"); }

int
CryptX_test(s)
        int  s
    CODE:
        RETVAL = s+1; /*xxx*/
    OUTPUT:
        RETVAL

###############################################################################

INCLUDE: CryptX_Digest.xs.inc
INCLUDE: CryptX_Cipher.xs.inc

INCLUDE: CryptX_Mac_F9.xs.inc
INCLUDE: CryptX_Mac_HMAC.xs.inc
INCLUDE: CryptX_Mac_OMAC.xs.inc
INCLUDE: CryptX_Mac_Pelican.xs.inc
INCLUDE: CryptX_Mac_PMAC.xs.inc
INCLUDE: CryptX_Mac_XCBC.xs.inc

