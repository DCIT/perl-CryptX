package CryptX;

use strict;
use warnings ;
our $VERSION = '0.088_001';

require XSLoader;
XSLoader::load('CryptX', $VERSION);

use Carp;
my $has_json;

BEGIN {
  $has_json = 1 if eval { require JSON; 1 };
}

sub _croak {
  die @_ if ref $_[0] || !$_[-1];
  if ($_[-1] =~ /^(.*)( at .+ line .+\n$)/s) {
    pop @_;
    push @_, $1;
  }
  die Carp::shortmess @_;
}

sub _decode_json {
  croak "FATAL: cannot find JSON module" if !$has_json;
  return JSON->new->utf8->decode(shift);
}

sub _encode_json {
  croak "FATAL: cannot find JSON module" if !$has_json;
  return JSON->new->utf8->canonical->encode(shift);
}

1;

=pod

=head1 NAME

CryptX - Cryptographic toolkit

=head1 SYNOPSIS

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

=head1 DESCRIPTION

Perl modules providing a cryptography based on L<LibTomCrypt|https://github.com/libtom/libtomcrypt> library.

This module mainly serves as the top-level distribution/documentation page. For actual work,
use one of the concrete modules listed below.

=head2 Algorithm Selection Guide

=head3 Symmetric Encryption (AEAD)

For new designs, prefer authenticated encryption (AEAD) over bare cipher modes:

=over

=item * B<ChaCha20-Poly1305> (L<Crypt::AuthEnc::ChaCha20Poly1305>) - Fast, constant-time,
widely deployed (TLS 1.3, WireGuard, SSH). Use this as the default AEAD choice.

=item * B<XChaCha20-Poly1305> (L<Crypt::AuthEnc::XChaCha20Poly1305>) - Extended 24-byte nonce
variant. Prefer over ChaCha20-Poly1305 when nonces are generated randomly.

=item * B<AES-GCM> (L<Crypt::AuthEnc::GCM>) - The standard AEAD mode for AES. Hardware-accelerated
on modern CPUs. Requires unique nonces; nonce reuse is catastrophic.

=item * B<AES-SIV> (L<Crypt::AuthEnc::SIV>) - Deterministic AEAD, nonce-misuse resistant.
Slightly slower but safer when nonce uniqueness cannot be guaranteed.

=item * B<AES-OCB> (L<Crypt::AuthEnc::OCB>) - Very fast single-pass AEAD. Check patent status
for your jurisdiction.

=item * B<AES-EAX> (L<Crypt::AuthEnc::EAX>) - Two-pass AEAD based on CTR+OMAC. No patents,
no nonce-length restrictions.

=item * B<AES-CCM> (L<Crypt::AuthEnc::CCM>) - Used in WiFi (WPA2) and Bluetooth. Requires
knowing the plaintext length in advance.

=back

=head3 Stream Ciphers

Stream ciphers encrypt data byte-by-byte without block padding. For most
applications prefer an AEAD mode (see above) which bundles encryption with
authentication. Use bare stream ciphers only when you handle authentication
separately.

=over

=item * B<ChaCha> (L<Crypt::Stream::ChaCha>) - The default stream cipher choice.
Same core as ChaCha20-Poly1305 without the built-in MAC.

=item * B<XChaCha> (L<Crypt::Stream::XChaCha>) - Extended 24-byte nonce variant of ChaCha.
Prefer when nonces are generated randomly.

=item * B<Salsa20> / B<XSalsa20> (L<Crypt::Stream::Salsa20>, L<Crypt::Stream::XSalsa20>) -
Predecessor of ChaCha. Prefer ChaCha for new designs; Salsa20 only for
interoperability (e.g. NaCl/libsodium).

=item * B<RC4> (L<Crypt::Stream::RC4>) - B<Broken; do not use for new designs.> Provided for
legacy interoperability only.

=item * B<Rabbit>, B<Sober128>, B<Sosemanuk> - Niche ciphers from the eSTREAM portfolio.
Use ChaCha unless a specific protocol requires one of these.

=back

=head3 Block Cipher Modes (without authentication)

Use these only when authentication is handled separately or not needed:

=over

=item * B<CTR> (L<Crypt::Mode::CTR>) - Turns a block cipher into a stream cipher. Parallelizable.

=item * B<CBC> (L<Crypt::Mode::CBC>) - Classic mode, needs padding. Prefer CTR or an AEAD mode.

=item * B<ECB> (L<Crypt::Mode::ECB>) - B<Insecure for most uses.> Each block encrypted independently.

=back

The individual L<Crypt::Cipher::AES>, L<Crypt::Cipher::Twofish>, etc. modules implement
raw single-block encryption and are rarely used directly. In almost all cases you should
use them through an AEAD mode (L<Crypt::AuthEnc::GCM>, L<Crypt::AuthEnc::CCM>) or a block
cipher mode (L<Crypt::Mode::CBC>, L<Crypt::Mode::CTR>) instead. When choosing a cipher,
B<AES> is the default; it is hardware-accelerated on most modern CPUs.

=head3 Hash Functions

=over

=item * B<SHA-256> / B<SHA-384> / B<SHA-512> (L<Crypt::Digest::SHA256>, etc.) - The default
choice for general hashing. Widely supported and well analyzed.

=item * B<SHA3-256> / B<SHA3-512> (L<Crypt::Digest::SHA3_256>, etc.) - Alternative to SHA-2
with a completely different construction (Keccak sponge).

=item * B<BLAKE2b> / B<BLAKE2s> (L<Crypt::Digest::BLAKE2b_256>, etc.) - Very fast, especially
in software. BLAKE2b for 64-bit platforms, BLAKE2s for 32-bit.

=item * B<SHAKE> / B<TurboSHAKE> / B<KangarooTwelve> - Extendable-output functions (XOFs).
Use when you need variable-length output.

=back

=head3 Message Authentication Codes

=over

=item * B<HMAC> (L<Crypt::Mac::HMAC>) - The standard MAC construction. Works with any hash.
Use HMAC-SHA256 as the default.

=item * B<Poly1305> (L<Crypt::Mac::Poly1305>) - One-time MAC, very fast. Used as part of
ChaCha20-Poly1305. Requires a unique key per message.

=item * B<BLAKE2b-MAC> (L<Crypt::Mac::BLAKE2b>) - Keyed BLAKE2. Faster than HMAC-SHA256 in
software.

=item * B<CMAC/OMAC> (L<Crypt::Mac::OMAC>) - Block-cipher-based MAC. Use when you already
have AES but not a hash function.

=back

=head3 Public-Key Cryptography

=over

=item * B<Ed25519> (L<Crypt::PK::Ed25519>) - Modern digital signatures. Fast, constant-time,
small keys/signatures. The default choice for new signature schemes.

=item * B<Ed448> (L<Crypt::PK::Ed448>) - Higher security margin than Ed25519 (~224-bit vs ~128-bit).

=item * B<X25519> (L<Crypt::PK::X25519>) - Elliptic-curve Diffie-Hellman key agreement. The
default choice for key exchange.

=item * B<X448> (L<Crypt::PK::X448>) - Higher security margin than X25519.

=item * B<ECDSA> (L<Crypt::PK::ECC>) - Widely used (TLS, Bitcoin). Prefer Ed25519 for new
designs unless ECDSA is required for interoperability.

=item * B<RSA> (L<Crypt::PK::RSA>) - Legacy but ubiquitous. Use 2048-bit keys minimum, 4096-bit
preferred. Prefer OAEP for encryption and PSS for signatures.

=item * B<DSA> (L<Crypt::PK::DSA>) - Legacy. Prefer Ed25519 or ECDSA.

=item * B<DH> (L<Crypt::PK::DH>) - Classic Diffie-Hellman. Prefer X25519 for new designs.

=back

=head3 Key Derivation

=over

=item * B<HKDF> (L<Crypt::KeyDerivation/hkdf>) - Extract-then-expand KDF. Use for deriving
keys from shared secrets (e.g. after ECDH).

=item * B<Argon2> (L<Crypt::KeyDerivation/argon2_pbkdf>) - Memory-hard password hashing. The
recommended choice for password storage.

=item * B<Scrypt> (L<Crypt::KeyDerivation/scrypt_pbkdf>) - Memory-hard KDF. Use Argon2 if available.

=item * B<PBKDF2> (L<Crypt::KeyDerivation/pbkdf2>) - Widely supported but CPU-only hardness.
Use Argon2 or Scrypt when possible.

=back

=head2 Error Handling

All CryptX modules report errors by calling C<croak> (from L<Carp>). Invalid parameters,
unsupported algorithms, wrong key sizes, malformed input, and internal library failures all
croak with a descriptive message. There are no error codes; catch exceptions with C<eval>
or L<Try::Tiny>.

The only methods that return C<undef> on failure instead of croaking are the C<*_decrypt_verify>
functions in the authenticated encryption modules
(L<Crypt::AuthEnc::GCM/gcm_decrypt_verify>,
L<Crypt::AuthEnc::CCM/ccm_decrypt_verify>,
L<Crypt::AuthEnc::EAX/eax_decrypt_verify>,
L<Crypt::AuthEnc::OCB/ocb_decrypt_verify>,
L<Crypt::AuthEnc::ChaCha20Poly1305/chacha20poly1305_decrypt_verify>,
L<Crypt::AuthEnc::XChaCha20Poly1305/xchacha20poly1305_decrypt_verify>,
L<Crypt::AuthEnc::SIV/siv_decrypt_verify>).
These return C<undef> when authentication fails, indicating the ciphertext was tampered with
or the wrong key/nonce was used.

=head2 Available Modules

=over

=item * Symmetric ciphers - see L<Crypt::Cipher> and related modules

L<Crypt::Cipher::AES>, L<Crypt::Cipher::Anubis>, L<Crypt::Cipher::Blowfish>, L<Crypt::Cipher::Camellia>, L<Crypt::Cipher::CAST5>, L<Crypt::Cipher::DES>,
L<Crypt::Cipher::DES_EDE>, L<Crypt::Cipher::IDEA>, L<Crypt::Cipher::KASUMI>, L<Crypt::Cipher::Khazad>, L<Crypt::Cipher::MULTI2>, L<Crypt::Cipher::Noekeon>,
L<Crypt::Cipher::RC2>, L<Crypt::Cipher::RC5>, L<Crypt::Cipher::RC6>, L<Crypt::Cipher::SAFERP>, L<Crypt::Cipher::SAFER_K128>, L<Crypt::Cipher::SAFER_K64>,
L<Crypt::Cipher::SAFER_SK128>, L<Crypt::Cipher::SAFER_SK64>, L<Crypt::Cipher::SEED>, L<Crypt::Cipher::Serpent>, L<Crypt::Cipher::Skipjack>,
L<Crypt::Cipher::Twofish>, L<Crypt::Cipher::XTEA>

=item * Block cipher modes

L<Crypt::Mode::CBC>, L<Crypt::Mode::CFB>, L<Crypt::Mode::CTR>, L<Crypt::Mode::ECB>, L<Crypt::Mode::OFB>

=item * Stream ciphers

L<Crypt::Stream::RC4>, L<Crypt::Stream::ChaCha>, L<Crypt::Stream::Salsa20>, L<Crypt::Stream::Sober128>,
L<Crypt::Stream::Sosemanuk>, L<Crypt::Stream::Rabbit>

=item * Authenticated encryption modes

L<Crypt::AuthEnc::CCM>, L<Crypt::AuthEnc::EAX>, L<Crypt::AuthEnc::GCM>, L<Crypt::AuthEnc::OCB>, L<Crypt::AuthEnc::ChaCha20Poly1305>

=item * Hash Functions - see L<Crypt::Digest> and related modules

L<Crypt::Digest::BLAKE2b_160>, L<Crypt::Digest::BLAKE2b_256>, L<Crypt::Digest::BLAKE2b_384>, L<Crypt::Digest::BLAKE2b_512>,
L<Crypt::Digest::BLAKE2s_128>, L<Crypt::Digest::BLAKE2s_160>, L<Crypt::Digest::BLAKE2s_224>, L<Crypt::Digest::BLAKE2s_256>,
L<Crypt::Digest::CHAES>, L<Crypt::Digest::MD2>, L<Crypt::Digest::MD4>, L<Crypt::Digest::MD5>, L<Crypt::Digest::RIPEMD128>, L<Crypt::Digest::RIPEMD160>,
L<Crypt::Digest::RIPEMD256>, L<Crypt::Digest::RIPEMD320>, L<Crypt::Digest::SHA1>, L<Crypt::Digest::SHA224>, L<Crypt::Digest::SHA256>, L<Crypt::Digest::SHA384>,
L<Crypt::Digest::SHA512>, L<Crypt::Digest::SHA512_224>, L<Crypt::Digest::SHA512_256>, L<Crypt::Digest::Tiger192>, L<Crypt::Digest::Whirlpool>,
L<Crypt::Digest::Keccak224>, L<Crypt::Digest::Keccak256>, L<Crypt::Digest::Keccak384>, L<Crypt::Digest::Keccak512>,
L<Crypt::Digest::SHA3_224>, L<Crypt::Digest::SHA3_256>, L<Crypt::Digest::SHA3_384>, L<Crypt::Digest::SHA3_512>, L<Crypt::Digest::SHAKE>

=item * Checksums

L<Crypt::Checksum::Adler32>, L<Crypt::Checksum::CRC32>

=item * Message Authentication Codes

L<Crypt::Mac::BLAKE2b>, L<Crypt::Mac::BLAKE2s>, L<Crypt::Mac::F9>, L<Crypt::Mac::HMAC>, L<Crypt::Mac::OMAC>,
L<Crypt::Mac::Pelican>, L<Crypt::Mac::PMAC>, L<Crypt::Mac::XCBC>, L<Crypt::Mac::Poly1305>

=item * Public key cryptography

L<Crypt::PK::RSA>, L<Crypt::PK::DSA>, L<Crypt::PK::ECC>, L<Crypt::PK::DH>, L<Crypt::PK::Ed25519>, L<Crypt::PK::X25519>

=item * Cryptographically secure random number generators - see L<Crypt::PRNG> and related modules

L<Crypt::PRNG::Fortuna>, L<Crypt::PRNG::Yarrow>, L<Crypt::PRNG::RC4>, L<Crypt::PRNG::Sober128>, L<Crypt::PRNG::ChaCha20>

=item * Key derivation functions - PBKDF1, PBKDF2, HKDF, Bcrypt, Scrypt, Argon2

L<Crypt::KeyDerivation>

=item * Other handy functions related to cryptography

L<Crypt::Misc>

=back

=head2 Diagnostic Functions

These low-level functions expose details of the bundled LibTomCrypt build.
They are intended for troubleshooting and bug reports, not for regular use.

=head3 ltc_build_settings

 my $str = CryptX::ltc_build_settings();

Returns a multi-line string describing every compile-time option that was
enabled when the bundled LibTomCrypt library was built (ciphers, hashes,
MACs, PK algorithms, compiler flags, etc.).

=head3 ltc_mp_name

 my $name = CryptX::ltc_mp_name();
 # e.g. "LTM" (LibTomMath)

Returns the name of the math provider back-end in use.

=head3 ltc_mp_bits_per_digit

 my $bits = CryptX::ltc_mp_bits_per_digit();
 # e.g. 60

Returns the number of bits per digit used by the math provider.

=head1 LICENSE

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=head1 COPYRIGHT

Copyright (c) 2013-2026 DCIT, a.s. L<https://www.dcit.cz> / Karel Miko

=cut
