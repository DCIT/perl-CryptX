# NAME

CryptX - Cryptographic toolkit

# DESCRIPTION

Perl modules providing a cryptography based on [LibTomCrypt](https://github.com/libtom/libtomcrypt) library.

- Symmetric ciphers - see [Crypt::Cipher](https://metacpan.org/pod/Crypt%3A%3ACipher) and related modules

    [Crypt::Cipher::AES](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AAES), [Crypt::Cipher::Anubis](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AAnubis), [Crypt::Cipher::Blowfish](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ABlowfish), [Crypt::Cipher::Camellia](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ACamellia), [Crypt::Cipher::CAST5](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ACAST5), [Crypt::Cipher::DES](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ADES),
    [Crypt::Cipher::DES\_EDE](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ADES_EDE), [Crypt::Cipher::IDEA](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AIDEA), [Crypt::Cipher::KASUMI](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AKASUMI), [Crypt::Cipher::Khazad](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AKhazad), [Crypt::Cipher::MULTI2](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AMULTI2), [Crypt::Cipher::Noekeon](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ANoekeon),
    [Crypt::Cipher::RC2](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ARC2), [Crypt::Cipher::RC5](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ARC5), [Crypt::Cipher::RC6](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ARC6), [Crypt::Cipher::SAFERP](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASAFERP), [Crypt::Cipher::SAFER\_K128](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASAFER_K128), [Crypt::Cipher::SAFER\_K64](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASAFER_K64),
    [Crypt::Cipher::SAFER\_SK128](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASAFER_SK128), [Crypt::Cipher::SAFER\_SK64](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASAFER_SK64), [Crypt::Cipher::SEED](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASEED), [Crypt::Cipher::Serpent](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASerpent), [Crypt::Cipher::Skipjack](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ASkipjack),
    [Crypt::Cipher::Twofish](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3ATwofish), [Crypt::Cipher::XTEA](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AXTEA)

- Block cipher modes

    [Crypt::Mode::CBC](https://metacpan.org/pod/Crypt%3A%3AMode%3A%3ACBC), [Crypt::Mode::CFB](https://metacpan.org/pod/Crypt%3A%3AMode%3A%3ACFB), [Crypt::Mode::CTR](https://metacpan.org/pod/Crypt%3A%3AMode%3A%3ACTR), [Crypt::Mode::ECB](https://metacpan.org/pod/Crypt%3A%3AMode%3A%3AECB), [Crypt::Mode::OFB](https://metacpan.org/pod/Crypt%3A%3AMode%3A%3AOFB)

- Stream ciphers

    [Crypt::Stream::RC4](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3ARC4), [Crypt::Stream::ChaCha](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3AChaCha), [Crypt::Stream::Salsa20](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3ASalsa20), [Crypt::Stream::Sober128](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3ASober128),
    [Crypt::Stream::Sosemanuk](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3ASosemanuk), [Crypt::Stream::Rabbit](https://metacpan.org/pod/Crypt%3A%3AStream%3A%3ARabbit)

- Authenticated encryption modes

    [Crypt::AuthEnc::CCM](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3ACCM), [Crypt::AuthEnc::EAX](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AEAX), [Crypt::AuthEnc::GCM](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AGCM), [Crypt::AuthEnc::OCB](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AOCB), [Crypt::AuthEnc::ChaCha20Poly1305](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AChaCha20Poly1305)

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

    [Crypt::PK::RSA](https://metacpan.org/pod/Crypt%3A%3APK%3A%3ARSA), [Crypt::PK::DSA](https://metacpan.org/pod/Crypt%3A%3APK%3A%3ADSA), [Crypt::PK::ECC](https://metacpan.org/pod/Crypt%3A%3APK%3A%3AECC), [Crypt::PK::DH](https://metacpan.org/pod/Crypt%3A%3APK%3A%3ADH), [Crypt::PK::Ed25519](https://metacpan.org/pod/Crypt%3A%3APK%3A%3AEd25519), [Crypt::PK::X25519](https://metacpan.org/pod/Crypt%3A%3APK%3A%3AX25519)

- Cryptographically secure random number generators - see [Crypt::PRNG](https://metacpan.org/pod/Crypt%3A%3APRNG) and related modules

    [Crypt::PRNG::Fortuna](https://metacpan.org/pod/Crypt%3A%3APRNG%3A%3AFortuna), [Crypt::PRNG::Yarrow](https://metacpan.org/pod/Crypt%3A%3APRNG%3A%3AYarrow), [Crypt::PRNG::RC4](https://metacpan.org/pod/Crypt%3A%3APRNG%3A%3ARC4), [Crypt::PRNG::Sober128](https://metacpan.org/pod/Crypt%3A%3APRNG%3A%3ASober128), [Crypt::PRNG::ChaCha20](https://metacpan.org/pod/Crypt%3A%3APRNG%3A%3AChaCha20)

- Key derivation functions - PBKDF1, PBKDF2 and HKDF

    [Crypt::KeyDerivation](https://metacpan.org/pod/Crypt%3A%3AKeyDerivation)

- Other handy functions related to cryptography

    [Crypt::Misc](https://metacpan.org/pod/Crypt%3A%3AMisc)

# LICENSE

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

# COPYRIGHT

Copyright (c) 2013-2021 DCIT, a.s. [https://www.dcit.cz](https://www.dcit.cz) / Karel Miko
