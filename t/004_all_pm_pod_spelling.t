use strict;
use warnings;

use Test::More;

plan skip_all => "set AUTHOR_MODE to enable this test (developer only!)" unless $ENV{AUTHOR_MODE};
plan skip_all => "File::Find not installed"             unless eval { require File::Find };
plan skip_all => "Test::Pod::Spelling not installed"    unless eval { require Test::Pod::Spelling };
plan skip_all => "Pod::Spelling::Ispell not installed"  unless eval { require Pod::Spelling::Ispell };
plan skip_all => "Lingua::Ispell not installed"         unless eval { require Lingua::Ispell };

Test::Pod::Spelling->import(
        spelling => {
                        import_speller => 'Pod::Spelling::Ispell',
                        allow_words => [qw(
                          ASN AES BLAKEb BLAKEs CPAN CRC ChaCha CryptX DCIT DER Diffie EAX ECCDH ECDH ECDSA Flickr HKDF JSON JWA JWK
                          Karel Miko OCB OCBv OID OMAC OO OpenSSL PBKDF PEM PKCS RIPEMD Rijndael SHA UUID RFC UUIDs PRK
                          decrypt decrypts interoperability cryptographically cryptographic octects
                          libtomcrypt libtommath
                          params paramshash irand perl endian zbase bumac bmac budigest bdigest md de
                          blakes_ blakeb_
                          XOR'ing XOR'ed XORed
                          keccak Ethereum recid
                          RC rand reseeding SSH CTR Poly CipherHash en aka
                          Scrypt Bcrypt bcrypt scrypt OpenBSD
                          XChaCha
                          AAD AEAD stateful
                          OAEP CMAC KDF XOFs WireGuard TLS Parallelizable WPA nonces PSS MACs
                          PNG ITU HDLC gzip PKZIP MODP subgroup eSTREAM NaCl libsodium
                          TurboSHAKE SIV KangarooTwelve XSalsa XOF RSA
                          stringifiable
                          stringification
                          stringified
                          RNG PRNG
                          CBC OFB ECB CFB
                          flexi MSB YY BER moduli SubjectPublicKeyInfo
                          rarr UTCTime TLV
                          OpenSSH codecs
                          undef adata
                        )]
                    },
);

plan tests => 119;

my @files;
File::Find::find({ wanted=>sub { push @files, $_ if /\.pm$/ }, no_chdir=>1 }, 'lib');

for my $m (sort @files) {
  Test::Pod::Spelling::pod_file_spelling_ok( $m, "Spelling in '$m'" );
}
