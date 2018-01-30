# NAME

CryptX - Cryptographic toolkit (self-contained, no external libraries needed)

# DESCRIPTION

Cryptography in CryptX is based on [https://github.com/libtom/libtomcrypt](https://github.com/libtom/libtomcrypt)

Available modules:

- Symmetric ciphers - see [Crypt::Cipher](https://metacpan.org/pod/Crypt::Cipher) and related modules

    [Crypt::Cipher::AES](https://metacpan.org/pod/Crypt::Cipher::AES), [Crypt::Cipher::Anubis](https://metacpan.org/pod/Crypt::Cipher::Anubis), [Crypt::Cipher::Blowfish](https://metacpan.org/pod/Crypt::Cipher::Blowfish), [Crypt::Cipher::Camellia](https://metacpan.org/pod/Crypt::Cipher::Camellia), [Crypt::Cipher::CAST5](https://metacpan.org/pod/Crypt::Cipher::CAST5), [Crypt::Cipher::DES](https://metacpan.org/pod/Crypt::Cipher::DES),
    [Crypt::Cipher::DES\_EDE](https://metacpan.org/pod/Crypt::Cipher::DES_EDE), [Crypt::Cipher::IDEA](https://metacpan.org/pod/Crypt::Cipher::IDEA), [Crypt::Cipher::KASUMI](https://metacpan.org/pod/Crypt::Cipher::KASUMI), [Crypt::Cipher::Khazad](https://metacpan.org/pod/Crypt::Cipher::Khazad), [Crypt::Cipher::MULTI2](https://metacpan.org/pod/Crypt::Cipher::MULTI2), [Crypt::Cipher::Noekeon](https://metacpan.org/pod/Crypt::Cipher::Noekeon),
    [Crypt::Cipher::RC2](https://metacpan.org/pod/Crypt::Cipher::RC2), [Crypt::Cipher::RC5](https://metacpan.org/pod/Crypt::Cipher::RC5), [Crypt::Cipher::RC6](https://metacpan.org/pod/Crypt::Cipher::RC6), [Crypt::Cipher::SAFERP](https://metacpan.org/pod/Crypt::Cipher::SAFERP), [Crypt::Cipher::SAFER\_K128](https://metacpan.org/pod/Crypt::Cipher::SAFER_K128), [Crypt::Cipher::SAFER\_K64](https://metacpan.org/pod/Crypt::Cipher::SAFER_K64),
    [Crypt::Cipher::SAFER\_SK128](https://metacpan.org/pod/Crypt::Cipher::SAFER_SK128), [Crypt::Cipher::SAFER\_SK64](https://metacpan.org/pod/Crypt::Cipher::SAFER_SK64), [Crypt::Cipher::SEED](https://metacpan.org/pod/Crypt::Cipher::SEED), [Crypt::Cipher::Serpent](https://metacpan.org/pod/Crypt::Cipher::Serpent), [Crypt::Cipher::Skipjack](https://metacpan.org/pod/Crypt::Cipher::Skipjack),
    [Crypt::Cipher::Twofish](https://metacpan.org/pod/Crypt::Cipher::Twofish), [Crypt::Cipher::XTEA](https://metacpan.org/pod/Crypt::Cipher::XTEA)

- Block cipher modes

    [Crypt::Mode::CBC](https://metacpan.org/pod/Crypt::Mode::CBC), [Crypt::Mode::CFB](https://metacpan.org/pod/Crypt::Mode::CFB), [Crypt::Mode::CTR](https://metacpan.org/pod/Crypt::Mode::CTR), [Crypt::Mode::ECB](https://metacpan.org/pod/Crypt::Mode::ECB), [Crypt::Mode::OFB](https://metacpan.org/pod/Crypt::Mode::OFB)

- Stream ciphers

    [Crypt::Stream::RC4](https://metacpan.org/pod/Crypt::Stream::RC4), [Crypt::Stream::ChaCha](https://metacpan.org/pod/Crypt::Stream::ChaCha), [Crypt::Stream::Salsa20](https://metacpan.org/pod/Crypt::Stream::Salsa20), [Crypt::Stream::Sober128](https://metacpan.org/pod/Crypt::Stream::Sober128),
    [Crypt::Stream::Sosemanuk](https://metacpan.org/pod/Crypt::Stream::Sosemanuk), [Crypt::Stream::Rabbit](https://metacpan.org/pod/Crypt::Stream::Rabbit)

- Authenticated encryption modes

    [Crypt::AuthEnc::CCM](https://metacpan.org/pod/Crypt::AuthEnc::CCM), [Crypt::AuthEnc::EAX](https://metacpan.org/pod/Crypt::AuthEnc::EAX), [Crypt::AuthEnc::GCM](https://metacpan.org/pod/Crypt::AuthEnc::GCM), [Crypt::AuthEnc::OCB](https://metacpan.org/pod/Crypt::AuthEnc::OCB), [Crypt::AuthEnc::ChaCha20Poly1305](https://metacpan.org/pod/Crypt::AuthEnc::ChaCha20Poly1305)

- Hash Functions - see [Crypt::Digest](https://metacpan.org/pod/Crypt::Digest) and related modules

    [Crypt::Digest::BLAKE2b\_160](https://metacpan.org/pod/Crypt::Digest::BLAKE2b_160), [Crypt::Digest::BLAKE2b\_256](https://metacpan.org/pod/Crypt::Digest::BLAKE2b_256), [Crypt::Digest::BLAKE2b\_384](https://metacpan.org/pod/Crypt::Digest::BLAKE2b_384), [Crypt::Digest::BLAKE2b\_512](https://metacpan.org/pod/Crypt::Digest::BLAKE2b_512),
    [Crypt::Digest::BLAKE2s\_128](https://metacpan.org/pod/Crypt::Digest::BLAKE2s_128), [Crypt::Digest::BLAKE2s\_160](https://metacpan.org/pod/Crypt::Digest::BLAKE2s_160), [Crypt::Digest::BLAKE2s\_224](https://metacpan.org/pod/Crypt::Digest::BLAKE2s_224), [Crypt::Digest::BLAKE2s\_256](https://metacpan.org/pod/Crypt::Digest::BLAKE2s_256),
    [Crypt::Digest::CHAES](https://metacpan.org/pod/Crypt::Digest::CHAES), [Crypt::Digest::MD2](https://metacpan.org/pod/Crypt::Digest::MD2), [Crypt::Digest::MD4](https://metacpan.org/pod/Crypt::Digest::MD4), [Crypt::Digest::MD5](https://metacpan.org/pod/Crypt::Digest::MD5), [Crypt::Digest::RIPEMD128](https://metacpan.org/pod/Crypt::Digest::RIPEMD128), [Crypt::Digest::RIPEMD160](https://metacpan.org/pod/Crypt::Digest::RIPEMD160),
    [Crypt::Digest::RIPEMD256](https://metacpan.org/pod/Crypt::Digest::RIPEMD256), [Crypt::Digest::RIPEMD320](https://metacpan.org/pod/Crypt::Digest::RIPEMD320), [Crypt::Digest::SHA1](https://metacpan.org/pod/Crypt::Digest::SHA1), [Crypt::Digest::SHA224](https://metacpan.org/pod/Crypt::Digest::SHA224), [Crypt::Digest::SHA256](https://metacpan.org/pod/Crypt::Digest::SHA256), [Crypt::Digest::SHA384](https://metacpan.org/pod/Crypt::Digest::SHA384),
    [Crypt::Digest::SHA512](https://metacpan.org/pod/Crypt::Digest::SHA512), [Crypt::Digest::SHA512\_224](https://metacpan.org/pod/Crypt::Digest::SHA512_224), [Crypt::Digest::SHA512\_256](https://metacpan.org/pod/Crypt::Digest::SHA512_256), [Crypt::Digest::Tiger192](https://metacpan.org/pod/Crypt::Digest::Tiger192), [Crypt::Digest::Whirlpool](https://metacpan.org/pod/Crypt::Digest::Whirlpool),
    [Crypt::Digest::SHA3\_224](https://metacpan.org/pod/Crypt::Digest::SHA3_224), [Crypt::Digest::SHA3\_256](https://metacpan.org/pod/Crypt::Digest::SHA3_256), [Crypt::Digest::SHA3\_384](https://metacpan.org/pod/Crypt::Digest::SHA3_384), [Crypt::Digest::SHA3\_512](https://metacpan.org/pod/Crypt::Digest::SHA3_512), [Crypt::Digest::SHAKE](https://metacpan.org/pod/Crypt::Digest::SHAKE)

- Checksums

    [Crypt::Checksum::Adler32](https://metacpan.org/pod/Crypt::Checksum::Adler32), [Crypt::Checksum::CRC32](https://metacpan.org/pod/Crypt::Checksum::CRC32)

- Message Authentication Codes

    [Crypt::Mac::BLAKE2b](https://metacpan.org/pod/Crypt::Mac::BLAKE2b), [Crypt::Mac::BLAKE2s](https://metacpan.org/pod/Crypt::Mac::BLAKE2s), [Crypt::Mac::F9](https://metacpan.org/pod/Crypt::Mac::F9), [Crypt::Mac::HMAC](https://metacpan.org/pod/Crypt::Mac::HMAC), [Crypt::Mac::OMAC](https://metacpan.org/pod/Crypt::Mac::OMAC),
    [Crypt::Mac::Pelican](https://metacpan.org/pod/Crypt::Mac::Pelican), [Crypt::Mac::PMAC](https://metacpan.org/pod/Crypt::Mac::PMAC), [Crypt::Mac::XCBC](https://metacpan.org/pod/Crypt::Mac::XCBC), [Crypt::Mac::Poly1305](https://metacpan.org/pod/Crypt::Mac::Poly1305)

- Public key cryptography

    [Crypt::PK::RSA](https://metacpan.org/pod/Crypt::PK::RSA), [Crypt::PK::DSA](https://metacpan.org/pod/Crypt::PK::DSA), [Crypt::PK::ECC](https://metacpan.org/pod/Crypt::PK::ECC), [Crypt::PK::DH](https://metacpan.org/pod/Crypt::PK::DH)

- Cryptographically secure random number generators - see [Crypt::PRNG](https://metacpan.org/pod/Crypt::PRNG) and related modules

    [Crypt::PRNG::Fortuna](https://metacpan.org/pod/Crypt::PRNG::Fortuna), [Crypt::PRNG::Yarrow](https://metacpan.org/pod/Crypt::PRNG::Yarrow), [Crypt::PRNG::RC4](https://metacpan.org/pod/Crypt::PRNG::RC4), [Crypt::PRNG::Sober128](https://metacpan.org/pod/Crypt::PRNG::Sober128), [Crypt::PRNG::ChaCha20](https://metacpan.org/pod/Crypt::PRNG::ChaCha20)

- Key derivation functions - PBKDF1, PBKDF2 and HKDF

    [Crypt::KeyDerivation](https://metacpan.org/pod/Crypt::KeyDerivation)

- Other handy functions related to cryptography

    [Crypt::Misc](https://metacpan.org/pod/Crypt::Misc)

# LICENSE

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

# COPYRIGHT

Copyright (c) 2013+ DCIT, a.s. [http://www.dcit.cz](http://www.dcit.cz) / Karel Miko
