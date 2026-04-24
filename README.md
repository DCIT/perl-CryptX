# NAME

CryptX - Cryptographic toolkit

# SYNOPSIS

    CryptX is the distribution entry point. In normal code, load one of the
    concrete modules listed below.

    use Crypt::Digest qw(digest_data_hex);
    my $data = 'hello world';
    my $sha256 = digest_data_hex('SHA256', $data);

    use Crypt::Cipher::AES;
    my $key = '1234567890abcdef';
    my $plaintext_block = '1234567890123456';
    my $aes = Crypt::Cipher::AES->new($key);
    my $block = $aes->encrypt($plaintext_block);

    use Crypt::AuthEnc::ChaCha20Poly1305 qw(chacha20poly1305_encrypt_authenticate);
    my $chacha_key = '1234567890abcdef1234567890abcdef'; # 32 bytes
    my $nonce = '123456789012';                          # 12 bytes
    my $adata = 'header';
    my $plaintext = 'hello world';
    my ($ciphertext, $tag) = chacha20poly1305_encrypt_authenticate($chacha_key, $nonce, $adata, $plaintext);

    use Crypt::PK::X25519;
    my $alice = Crypt::PK::X25519->new->generate_key;
    my $bob = Crypt::PK::X25519->new->generate_key;
    my $shared_secret = $alice->shared_secret($bob);

# DESCRIPTION

Perl modules providing a cryptography based on [LibTomCrypt](https://github.com/libtom/libtomcrypt) library.

This module mainly serves as the top-level distribution/documentation page. For actual work,
use one of the concrete modules listed below.

## Algorithm Selection Guide

### Symmetric Encryption (AEAD)

For new designs, prefer authenticated encryption (AEAD) over bare cipher modes:

- **ChaCha20-Poly1305** ([Crypt::AuthEnc::ChaCha20Poly1305](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AChaCha20Poly1305)) - Fast, constant-time,
widely deployed (TLS 1.3, WireGuard, SSH). Use this as the default AEAD choice.
- **XChaCha20-Poly1305** ([Crypt::AuthEnc::XChaCha20Poly1305](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AXChaCha20Poly1305)) - Extended 24-byte nonce
variant. Prefer over ChaCha20-Poly1305 when nonces are generated randomly.
- **AES-GCM** ([Crypt::AuthEnc::GCM](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AGCM)) - The standard AEAD mode for AES. Hardware-accelerated
on modern CPUs. Requires unique nonces; nonce reuse is catastrophic.
- **AES-SIV** ([Crypt::AuthEnc::SIV](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3ASIV)) - Deterministic AEAD, nonce-misuse resistant.
Slightly slower but safer when nonce uniqueness cannot be guaranteed.
- **AES-OCB** ([Crypt::AuthEnc::OCB](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AOCB)) - Very fast single-pass AEAD. Check patent status
for your jurisdiction.
- **AES-EAX** ([Crypt::AuthEnc::EAX](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AEAX)) - Two-pass AEAD based on CTR+OMAC. No patents,
no nonce-length restrictions.
- **AES-CCM** ([Crypt::AuthEnc::CCM](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3ACCM)) - Used in WiFi (WPA2) and Bluetooth. Requires
knowing the plaintext length in advance.

### Stream Ciphers

Stream ciphers encrypt data byte-by-byte without block padding. For most
applications prefer an AEAD mode (see above) which bundles encryption with
authentication. Use bare stream ciphers only when you handle authentication
separately.

- **ChaCha** ([Crypt::Stream::ChaCha](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3AChaCha)) - The default stream cipher choice.
Same core as ChaCha20-Poly1305 without the built-in MAC.
- **XChaCha** ([Crypt::Stream::XChaCha](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3AXChaCha)) - Extended 24-byte nonce variant of ChaCha.
Prefer when nonces are generated randomly.
- **Salsa20** / **XSalsa20** ([Crypt::Stream::Salsa20](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3ASalsa20), [Crypt::Stream::XSalsa20](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3AXSalsa20)) -
Predecessor of ChaCha. Prefer ChaCha for new designs; Salsa20 only for
interoperability (e.g. NaCl/libsodium).
- **RC4** ([Crypt::Stream::RC4](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3ARC4)) - **Broken; do not use for new designs.** Provided for
legacy interoperability only.
- **Rabbit**, **Sober128**, **Sosemanuk** - Niche ciphers from the eSTREAM portfolio.
Use ChaCha unless a specific protocol requires one of these.

### Block Cipher Modes (without authentication)

Use these only when authentication is handled separately or not needed:

- **CTR** ([Crypt::Mode::CTR](https://metacpan.org/pod/Crypt%3A%3AMode%3A%3ACTR)) - Turns a block cipher into a stream cipher. Parallelizable.
- **CBC** ([Crypt::Mode::CBC](https://metacpan.org/pod/Crypt%3A%3AMode%3A%3ACBC)) - Classic mode, needs padding. Prefer CTR or an AEAD mode.
- **ECB** ([Crypt::Mode::ECB](https://metacpan.org/pod/Crypt%3A%3AMode%3A%3AECB)) - **Insecure for most uses.** Each block encrypted independently.

The individual [Crypt::Cipher::AES](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AAES), [Crypt::Cipher::Twofish](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ATwofish), etc. modules implement
raw single-block encryption and are rarely used directly. In almost all cases you should
use them through an AEAD mode ([Crypt::AuthEnc::GCM](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AGCM), [Crypt::AuthEnc::CCM](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3ACCM)) or a block
cipher mode ([Crypt::Mode::CBC](https://metacpan.org/pod/Crypt%3A%3AMode%3A%3ACBC), [Crypt::Mode::CTR](https://metacpan.org/pod/Crypt%3A%3AMode%3A%3ACTR)) instead. When choosing a cipher,
**AES** is the default; it is hardware-accelerated on most modern CPUs.

### Hash Functions

- **SHA-256** / **SHA-384** / **SHA-512** ([Crypt::Digest::SHA256](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ASHA256), etc.) - The default
choice for general hashing. Widely supported and well analyzed.
- **SHA3-256** / **SHA3-512** ([Crypt::Digest::SHA3\_256](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ASHA3_256), etc.) - Alternative to SHA-2
with a completely different construction (Keccak sponge).
- **BLAKE2b** / **BLAKE2s** ([Crypt::Digest::BLAKE2b\_256](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ABLAKE2b_256), etc.) - Very fast, especially
in software. BLAKE2b for 64-bit platforms, BLAKE2s for 32-bit.
- **SHAKE** / **TurboSHAKE** / **KangarooTwelve** - Extendable-output functions (XOFs).
Use when you need variable-length output.

### Message Authentication Codes

- **HMAC** ([Crypt::Mac::HMAC](https://metacpan.org/pod/Crypt%3A%3AMac%3A%3AHMAC)) - The standard MAC construction. Works with any hash.
Use HMAC-SHA256 as the default.
- **Poly1305** ([Crypt::Mac::Poly1305](https://metacpan.org/pod/Crypt%3A%3AMac%3A%3APoly1305)) - One-time MAC, very fast. Used as part of
ChaCha20-Poly1305. Requires a unique key per message.
- **BLAKE2b-MAC** ([Crypt::Mac::BLAKE2b](https://metacpan.org/pod/Crypt%3A%3AMac%3A%3ABLAKE2b)) - Keyed BLAKE2. Faster than HMAC-SHA256 in
software.
- **CMAC/OMAC** ([Crypt::Mac::OMAC](https://metacpan.org/pod/Crypt%3A%3AMac%3A%3AOMAC)) - Block-cipher-based MAC. Use when you already
have AES but not a hash function.

### Public-Key Cryptography

- **Ed25519** ([Crypt::PK::Ed25519](https://metacpan.org/pod/Crypt%3A%3APK%3A%3AEd25519)) - Modern digital signatures. Fast, constant-time,
small keys/signatures. The default choice for new signature schemes.
- **Ed448** ([Crypt::PK::Ed448](https://metacpan.org/pod/Crypt%3A%3APK%3A%3AEd448)) - Higher security margin than Ed25519 (~224-bit vs ~128-bit).
- **X25519** ([Crypt::PK::X25519](https://metacpan.org/pod/Crypt%3A%3APK%3A%3AX25519)) - Elliptic-curve Diffie-Hellman key agreement. The
default choice for key exchange.
- **X448** ([Crypt::PK::X448](https://metacpan.org/pod/Crypt%3A%3APK%3A%3AX448)) - Higher security margin than X25519.
- **ECDSA** ([Crypt::PK::ECC](https://metacpan.org/pod/Crypt%3A%3APK%3A%3AECC)) - Widely used (TLS, Bitcoin). Prefer Ed25519 for new
designs unless ECDSA is required for interoperability.
- **RSA** ([Crypt::PK::RSA](https://metacpan.org/pod/Crypt%3A%3APK%3A%3ARSA)) - Legacy but ubiquitous. Use 2048-bit keys minimum, 4096-bit
preferred. Prefer OAEP for encryption and PSS for signatures.
- **DSA** ([Crypt::PK::DSA](https://metacpan.org/pod/Crypt%3A%3APK%3A%3ADSA)) - Legacy. Prefer Ed25519 or ECDSA.
- **DH** ([Crypt::PK::DH](https://metacpan.org/pod/Crypt%3A%3APK%3A%3ADH)) - Classic Diffie-Hellman. Prefer X25519 for new designs.

### Key Derivation

- **HKDF** (["hkdf" in Crypt::KeyDerivation](https://metacpan.org/pod/Crypt%3A%3AKeyDerivation#hkdf)) - Extract-then-expand KDF. Use for deriving
keys from shared secrets (e.g. after ECDH).
- **Argon2** (["argon2\_pbkdf" in Crypt::KeyDerivation](https://metacpan.org/pod/Crypt%3A%3AKeyDerivation#argon2_pbkdf)) - Memory-hard password hashing. The
recommended choice for password storage.
- **Scrypt** (["scrypt\_pbkdf" in Crypt::KeyDerivation](https://metacpan.org/pod/Crypt%3A%3AKeyDerivation#scrypt_pbkdf)) - Memory-hard KDF. Use Argon2 if available.
- **PBKDF2** (["pbkdf2" in Crypt::KeyDerivation](https://metacpan.org/pod/Crypt%3A%3AKeyDerivation#pbkdf2)) - Widely supported but CPU-only hardness.
Use Argon2 or Scrypt when possible.

## Error Handling

All CryptX modules report errors by calling `croak` (from [Carp](https://metacpan.org/pod/Carp)). Invalid parameters,
unsupported algorithms, wrong key sizes, malformed input, and internal library failures all
croak with a descriptive message. There are no error codes; catch exceptions with `eval`
or [Try::Tiny](https://metacpan.org/pod/Try%3A%3ATiny).

The only methods that return `undef` on failure instead of croaking are the `*_decrypt_verify`
functions in the authenticated encryption modules
(["gcm\_decrypt\_verify" in Crypt::AuthEnc::GCM](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AGCM#gcm_decrypt_verify),
["ccm\_decrypt\_verify" in Crypt::AuthEnc::CCM](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3ACCM#ccm_decrypt_verify),
["eax\_decrypt\_verify" in Crypt::AuthEnc::EAX](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AEAX#eax_decrypt_verify),
["ocb\_decrypt\_verify" in Crypt::AuthEnc::OCB](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AOCB#ocb_decrypt_verify),
["chacha20poly1305\_decrypt\_verify" in Crypt::AuthEnc::ChaCha20Poly1305](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AChaCha20Poly1305#chacha20poly1305_decrypt_verify),
["xchacha20poly1305\_decrypt\_verify" in Crypt::AuthEnc::XChaCha20Poly1305](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AXChaCha20Poly1305#xchacha20poly1305_decrypt_verify),
["siv\_decrypt\_verify" in Crypt::AuthEnc::SIV](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3ASIV#siv_decrypt_verify)).
These return `undef` when authentication fails, indicating the ciphertext was tampered with
or the wrong key/nonce was used.

## Available Modules

- Symmetric ciphers - see [Crypt::Cipher](https://metacpan.org/pod/Crypt%3A%3ACipher) and related modules

    [Crypt::Cipher::AES](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AAES), [Crypt::Cipher::Anubis](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AAnubis), [Crypt::Cipher::Blowfish](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ABlowfish), [Crypt::Cipher::Camellia](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ACamellia), [Crypt::Cipher::CAST5](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ACAST5), [Crypt::Cipher::DES](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ADES),
    [Crypt::Cipher::DES\_EDE](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ADES_EDE), [Crypt::Cipher::IDEA](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AIDEA), [Crypt::Cipher::KASUMI](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AKASUMI), [Crypt::Cipher::Khazad](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AKhazad), [Crypt::Cipher::MULTI2](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AMULTI2), [Crypt::Cipher::Noekeon](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ANoekeon),
    [Crypt::Cipher::RC2](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ARC2), [Crypt::Cipher::RC5](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ARC5), [Crypt::Cipher::RC6](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ARC6), [Crypt::Cipher::SAFERP](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASAFERP), [Crypt::Cipher::SAFER\_K128](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASAFER_K128), [Crypt::Cipher::SAFER\_K64](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASAFER_K64),
    [Crypt::Cipher::SAFER\_SK128](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASAFER_SK128), [Crypt::Cipher::SAFER\_SK64](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASAFER_SK64), [Crypt::Cipher::SEED](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASEED), [Crypt::Cipher::Serpent](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASerpent), [Crypt::Cipher::Skipjack](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASkipjack),
    [Crypt::Cipher::Twofish](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ATwofish), [Crypt::Cipher::XTEA](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AXTEA)

- Block cipher modes

    [Crypt::Mode::CBC](https://metacpan.org/pod/Crypt%3A%3AMode%3A%3ACBC), [Crypt::Mode::CFB](https://metacpan.org/pod/Crypt%3A%3AMode%3A%3ACFB), [Crypt::Mode::CTR](https://metacpan.org/pod/Crypt%3A%3AMode%3A%3ACTR), [Crypt::Mode::ECB](https://metacpan.org/pod/Crypt%3A%3AMode%3A%3AECB), [Crypt::Mode::OFB](https://metacpan.org/pod/Crypt%3A%3AMode%3A%3AOFB)

- Stream ciphers

    [Crypt::Stream::RC4](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3ARC4), [Crypt::Stream::ChaCha](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3AChaCha), [Crypt::Stream::XChaCha](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3AXChaCha), [Crypt::Stream::Salsa20](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3ASalsa20), [Crypt::Stream::XSalsa20](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3AXSalsa20), [Crypt::Stream::Sober128](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3ASober128),
    [Crypt::Stream::Sosemanuk](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3ASosemanuk), [Crypt::Stream::Rabbit](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3ARabbit)

- Authenticated encryption modes

    [Crypt::AuthEnc::CCM](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3ACCM), [Crypt::AuthEnc::EAX](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AEAX), [Crypt::AuthEnc::GCM](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AGCM), [Crypt::AuthEnc::OCB](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AOCB), [Crypt::AuthEnc::ChaCha20Poly1305](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AChaCha20Poly1305), [Crypt::AuthEnc::XChaCha20Poly1305](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AXChaCha20Poly1305)

- Hash Functions - see [Crypt::Digest](https://metacpan.org/pod/Crypt%3A%3ADigest) and related modules

    [Crypt::Digest::BLAKE2b\_160](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ABLAKE2b_160), [Crypt::Digest::BLAKE2b\_256](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ABLAKE2b_256), [Crypt::Digest::BLAKE2b\_384](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ABLAKE2b_384), [Crypt::Digest::BLAKE2b\_512](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ABLAKE2b_512),
    [Crypt::Digest::BLAKE2s\_128](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ABLAKE2s_128), [Crypt::Digest::BLAKE2s\_160](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ABLAKE2s_160), [Crypt::Digest::BLAKE2s\_224](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ABLAKE2s_224), [Crypt::Digest::BLAKE2s\_256](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ABLAKE2s_256),
    [Crypt::Digest::CHAES](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ACHAES), [Crypt::Digest::MD2](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3AMD2), [Crypt::Digest::MD4](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3AMD4), [Crypt::Digest::MD5](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3AMD5), [Crypt::Digest::RIPEMD128](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ARIPEMD128), [Crypt::Digest::RIPEMD160](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ARIPEMD160),
    [Crypt::Digest::RIPEMD256](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ARIPEMD256), [Crypt::Digest::RIPEMD320](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ARIPEMD320), [Crypt::Digest::SHA1](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ASHA1), [Crypt::Digest::SHA224](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ASHA224), [Crypt::Digest::SHA256](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ASHA256), [Crypt::Digest::SHA384](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ASHA384),
    [Crypt::Digest::SHA512](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ASHA512), [Crypt::Digest::SHA512\_224](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ASHA512_224), [Crypt::Digest::SHA512\_256](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ASHA512_256), [Crypt::Digest::Tiger192](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ATiger192), [Crypt::Digest::Whirlpool](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3AWhirlpool),
    [Crypt::Digest::Keccak224](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3AKeccak224), [Crypt::Digest::Keccak256](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3AKeccak256), [Crypt::Digest::Keccak384](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3AKeccak384), [Crypt::Digest::Keccak512](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3AKeccak512),
    [Crypt::Digest::SHA3\_224](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ASHA3_224), [Crypt::Digest::SHA3\_256](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ASHA3_256), [Crypt::Digest::SHA3\_384](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ASHA3_384), [Crypt::Digest::SHA3\_512](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ASHA3_512), [Crypt::Digest::SHAKE](https://metacpan.org/pod/Crypt%3A%3ADigest%3A%3ASHAKE)

- Checksums

    [Crypt::Checksum::Adler32](https://metacpan.org/pod/Crypt%3A%3AChecksum%3A%3AAdler32), [Crypt::Checksum::CRC32](https://metacpan.org/pod/Crypt%3A%3AChecksum%3A%3ACRC32)

- Message Authentication Codes

    [Crypt::Mac::BLAKE2b](https://metacpan.org/pod/Crypt%3A%3AMac%3A%3ABLAKE2b), [Crypt::Mac::BLAKE2s](https://metacpan.org/pod/Crypt%3A%3AMac%3A%3ABLAKE2s), [Crypt::Mac::F9](https://metacpan.org/pod/Crypt%3A%3AMac%3A%3AF9), [Crypt::Mac::HMAC](https://metacpan.org/pod/Crypt%3A%3AMac%3A%3AHMAC), [Crypt::Mac::OMAC](https://metacpan.org/pod/Crypt%3A%3AMac%3A%3AOMAC),
    [Crypt::Mac::Pelican](https://metacpan.org/pod/Crypt%3A%3AMac%3A%3APelican), [Crypt::Mac::PMAC](https://metacpan.org/pod/Crypt%3A%3AMac%3A%3APMAC), [Crypt::Mac::XCBC](https://metacpan.org/pod/Crypt%3A%3AMac%3A%3AXCBC), [Crypt::Mac::Poly1305](https://metacpan.org/pod/Crypt%3A%3AMac%3A%3APoly1305)

- Public key cryptography

    [Crypt::PK::RSA](https://metacpan.org/pod/Crypt%3A%3APK%3A%3ARSA), [Crypt::PK::DSA](https://metacpan.org/pod/Crypt%3A%3APK%3A%3ADSA), [Crypt::PK::ECC](https://metacpan.org/pod/Crypt%3A%3APK%3A%3AECC), [Crypt::PK::DH](https://metacpan.org/pod/Crypt%3A%3APK%3A%3ADH), [Crypt::PK::Ed25519](https://metacpan.org/pod/Crypt%3A%3APK%3A%3AEd25519), [Crypt::PK::X25519](https://metacpan.org/pod/Crypt%3A%3APK%3A%3AX25519), [Crypt::PK::Ed448](https://metacpan.org/pod/Crypt%3A%3APK%3A%3AEd448), [Crypt::PK::X448](https://metacpan.org/pod/Crypt%3A%3APK%3A%3AX448)

- Cryptographically secure random number generators - see [Crypt::PRNG](https://metacpan.org/pod/Crypt%3A%3APRNG) and related modules

    [Crypt::PRNG::Fortuna](https://metacpan.org/pod/Crypt%3A%3APRNG%3A%3AFortuna), [Crypt::PRNG::Yarrow](https://metacpan.org/pod/Crypt%3A%3APRNG%3A%3AYarrow), [Crypt::PRNG::RC4](https://metacpan.org/pod/Crypt%3A%3APRNG%3A%3ARC4), [Crypt::PRNG::Sober128](https://metacpan.org/pod/Crypt%3A%3APRNG%3A%3ASober128), [Crypt::PRNG::ChaCha20](https://metacpan.org/pod/Crypt%3A%3APRNG%3A%3AChaCha20)

- Key derivation functions - PBKDF1, PBKDF2, HKDF, Bcrypt, Scrypt, Argon2

    [Crypt::KeyDerivation](https://metacpan.org/pod/Crypt%3A%3AKeyDerivation)

- Other handy functions related to cryptography

    [Crypt::Misc](https://metacpan.org/pod/Crypt%3A%3AMisc)

## Diagnostic Functions

These low-level functions expose details of the bundled LibTomCrypt build.
They are intended for troubleshooting and bug reports, not for regular use.

### ltc\_build\_settings

    my $str = CryptX::ltc_build_settings();

Returns a multi-line string describing every compile-time option that was
enabled when the bundled LibTomCrypt library was built (ciphers, hashes,
MACs, PK algorithms, compiler flags, etc.).

### ltc\_mp\_name

    my $name = CryptX::ltc_mp_name();
    # e.g. "LTM" (LibTomMath)

Returns the name of the math provider back-end in use.

### ltc\_mp\_bits\_per\_digit

    my $bits = CryptX::ltc_mp_bits_per_digit();
    # e.g. 60

Returns the number of bits per digit used by the math provider.

# LICENSE

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

# COPYRIGHT

Copyright (c) 2013-2026 DCIT, a.s. [https://www.dcit.cz](https://www.dcit.cz) / Karel Miko
