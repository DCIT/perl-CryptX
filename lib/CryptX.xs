#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#undef LTC_SOURCE
#include "tomcrypt.h"
#include "tommath.h"

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

typedef struct ccm_struct {             /* used by Crypt::AuthEnc::CCM */
  int id;
} *Crypt__AuthEnc__CCM;

typedef struct eax_struct {             /* used by Crypt::AuthEnc::EAX */
  eax_state state;
  int id;
} *Crypt__AuthEnc__EAX;

typedef struct gcm_struct {             /* used by Crypt::AuthEnc::GCM */
  gcm_state state;
  int id;
} *Crypt__AuthEnc__GCM;

typedef struct ocb_struct {             /* used by Crypt::AuthEnc::OCB */
  ocb3_state state;
  int id;
} *Crypt__AuthEnc__OCB;

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

typedef struct cbc_struct {             /* used by Crypt::Mode::CBC */
  int cipher_id, cipher_rounds;
  symmetric_CBC state;
  unsigned char pad[MAXBLOCKSIZE];
  int padlen;
  int padding_mode;
  int direction;
  int id;
} *Crypt__Mode__CBC;

typedef struct ecb_struct {             /* used by Crypt::Mode::ECB */
  int cipher_id, cipher_rounds;
  symmetric_ECB state;
  unsigned char pad[MAXBLOCKSIZE];
  int padlen;
  int padding_mode;
  int direction;
  int id;
} *Crypt__Mode__ECB;

typedef struct cfb_struct {             /* used by Crypt::Mode::CFB */
  int cipher_id, cipher_rounds;
  symmetric_CFB state;
  int direction;
  int id;
} *Crypt__Mode__CFB;

typedef struct ctr_struct {             /* used by Crypt::Mode::CTR */
  int cipher_id, cipher_rounds;
  int ctr_mode_param;
  symmetric_CTR state;
  int direction;
  int id;
} *Crypt__Mode__CTR;

typedef struct f8_struct {              /* used by Crypt::Mode::F8 */
  int cipher_id, cipher_rounds;
  symmetric_F8 state;
  int direction;
  int id;
} *Crypt__Mode__F8;

typedef struct lrw_struct {             /* used by Crypt::Mode::LRW */
  int cipher_id, cipher_rounds;
  symmetric_LRW state;
  int direction;
  int id;
} *Crypt__Mode__LRW;

typedef struct ofb_struct {             /* used by Crypt::Mode::OFB */
  int cipher_id, cipher_rounds;
  symmetric_OFB state;
  int direction;
  int id;
} *Crypt__Mode__OFB;

typedef struct xts_struct {             /* used by Crypt::Mode::XTS */
  int cipher_id, cipher_rounds;
  symmetric_xts state;
  int direction;
  int id;
} *Crypt__Mode__XTS;

typedef struct prng_struct {            /* used by Crypt::PRNG */
  prng_state state;
  struct ltc_prng_descriptor *desc;
  IV last_pid;
  int id;
} *Crypt__PRNG;

typedef struct rsa_struct {             /* used by Crypt::PK::RSA */
  prng_state yarrow_prng_state;
  int yarrow_prng_index;
  rsa_key key;
  int id;
} *Crypt__PK__RSA;

typedef struct dsa_struct {             /* used by Crypt::PK::DSA */
  prng_state yarrow_prng_state;
  int yarrow_prng_index;
  dsa_key key;
  int id;
} *Crypt__PK__DSA;

typedef struct dh_struct {              /* used by Crypt::PK::DH */
  prng_state yarrow_prng_state;
  int yarrow_prng_index;
  dh_key key;
  int id;
} *Crypt__PK__DH;

typedef struct ecc_struct {             /* used by Crypt::PK::ECC */
  prng_state yarrow_prng_state;
  int yarrow_prng_index;
  ecc_key key;
  int id;
} *Crypt__PK__ECC;

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
    /* --- */
    if(register_prng(&fortuna_desc)==-1)       { croak("FATAL: cannot register_prng fortuna"); }
    if(register_prng(&rc4_desc)==-1)           { croak("FATAL: cannot register_prng rc4"); }
    if(register_prng(&sober128_desc)==-1)      { croak("FATAL: cannot register_prng sober128"); }
    if(register_prng(&yarrow_desc)==-1)        { croak("FATAL: cannot register_prng yarrow"); }
    /* --- */
#ifdef TFM_DESC
    ltc_mp = tfm_desc;
#else
    ltc_mp = ltm_desc;
#endif

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

INCLUDE: CryptX_AuthEnc_EAX.xs.inc
INCLUDE: CryptX_AuthEnc_GCM.xs.inc
INCLUDE: CryptX_AuthEnc_OCB.xs.inc
INCLUDE: CryptX_AuthEnc_CCM.xs.inc

INCLUDE: CryptX_Mac_F9.xs.inc
INCLUDE: CryptX_Mac_HMAC.xs.inc
INCLUDE: CryptX_Mac_OMAC.xs.inc
INCLUDE: CryptX_Mac_Pelican.xs.inc
INCLUDE: CryptX_Mac_PMAC.xs.inc
INCLUDE: CryptX_Mac_XCBC.xs.inc
 
INCLUDE: CryptX_Mode_CBC.xs.inc
INCLUDE: CryptX_Mode_ECB.xs.inc
INCLUDE: CryptX_Mode_CFB.xs.inc
INCLUDE: CryptX_Mode_OFB.xs.inc
INCLUDE: CryptX_Mode_CTR.xs.inc
#INCLUDE: CryptX_Mode_F8.xs.inc
#INCLUDE: CryptX_Mode_LRW.xs.inc
#INCLUDE: CryptX_Mode_XTS.xs.inc

INCLUDE: CryptX_PRNG.xs.inc

INCLUDE: CryptX_PK_RSA.xs.inc
INCLUDE: CryptX_PK_DSA.xs.inc
INCLUDE: CryptX_PK_DH.xs.inc
INCLUDE: CryptX_PK_ECC.xs.inc

INCLUDE: CryptX_KeyDerivation.xs.inc
