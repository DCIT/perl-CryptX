use strict;
use warnings;
use Test::More;
use Devel::Peek ();

use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use Crypt::AuthEnc::ChaCha20Poly1305 qw(chacha20poly1305_encrypt_authenticate chacha20poly1305_decrypt_verify);
use Crypt::AuthEnc::CCM qw(ccm_encrypt_authenticate ccm_decrypt_verify);
use Crypt::AuthEnc::EAX qw(eax_encrypt_authenticate eax_decrypt_verify);
use Crypt::AuthEnc::OCB qw(ocb_encrypt_authenticate ocb_decrypt_verify);
use Crypt::AuthEnc::SIV qw(siv_encrypt_authenticate siv_decrypt_verify);
use Crypt::AuthEnc::GCMSIV qw(gcm_siv_encrypt_authenticate gcm_siv_decrypt_verify);
use Crypt::Cipher;
use Crypt::Mode::CBC;
use Crypt::Mode::CTR;
use Crypt::Mode::XTS;
use Crypt::Stream::ChaCha;
use Crypt::PRNG qw(random_bytes);
use Crypt::KeyDerivation qw(pbkdf2 hkdf);
use Crypt::Digest::SHAKE;
use Crypt::Misc qw(encode_b64 decode_b64 increment_octets_be);

# Every SV handed back to perl must obey the PV invariant SvPVX[SvCUR] == '\0';
# perl's string-to-number conversion (Atof) relies on it and reads past SvCUR
# otherwise. Freed heap chunks are poisoned with digit bytes so that a missing
# terminator is actually visible in Devel::Peek::Dump output.

# Devel::Peek::Dump writes to fd 2; capture it at the descriptor level.
open my $SAVED_ERR, '>&', \*STDERR or die "dup stderr: $!";
open my $PEEK, '+>', undef or die "temp file: $!";

sub is_terminated {
    my ($ref) = @_;
    open STDERR, '>&', $PEEK or die "redirect stderr: $!";
    seek $PEEK, 0, 0;
    truncate $PEEK, 0;
    Devel::Peek::Dump($$ref);
    open STDERR, '>&', $SAVED_ERR or die "restore stderr: $!";
    seek $PEEK, 0, 0;
    my $out = do { local $/; <$PEEK> };
    my ($pv) = $out =~ /^\s*PV = 0x[0-9a-f]+ (.*)$/m;
    return -1 unless defined $pv;       # no PV buffer at all
    return $pv =~ /\\0(?:\s*\[[^\]]*\])?\s*$/ ? 1 : 0;
}

sub poison {   # fill freed chunks of all relevant size classes with digits
    my @junk;
    for my $size (8 .. 96) { push @junk, '7' x $size for 1 .. 6 }
    @junk = ();
    return;
}

sub D { my $len = shift; '1' . ('0' x ($len - 1)) }   # $len digit bytes

{
    my $selftest = 'abc123';
    if (is_terminated(\$selftest) != 1) {
        plan skip_all => 'cannot parse Devel::Peek::Dump output on this perl';
    }
}

plan tests => 33;

my $key  = 'K' x 32;
my $k16  = 'K' x 16;
my $kxts = 'K' x 32 . 'L' x 32;
my $iv12 = 'I' x 12;
my $iv16 = 'I' x 16;
my $n13  = 'N' x 13;

my %cases = (
    'gcm one-shot ct'          => sub { my ($c,$t) = gcm_encrypt_authenticate('AES',$key,$iv12,'',D($_[0])); \$c },
    'gcm one-shot pt'          => sub { my ($c,$t) = gcm_encrypt_authenticate('AES',$key,$iv12,'',D($_[0]));
                                        my $p = gcm_decrypt_verify('AES',$key,$iv12,'',$c,$t); \$p },
    'gcm OO encrypt_add'       => sub { my $x = Crypt::AuthEnc::GCM->new('AES',$key,$iv12)->encrypt_add(D($_[0])); \$x },
    'gcm OO decrypt_add'       => sub { my $x = Crypt::AuthEnc::GCM->new('AES',$key,$iv12)->decrypt_add(D($_[0])); \$x },
    'chacha20poly1305 ct'      => sub { my ($c,$t) = chacha20poly1305_encrypt_authenticate($key,$iv12,'',D($_[0])); \$c },
    'chacha20poly1305 pt'      => sub { my ($c,$t) = chacha20poly1305_encrypt_authenticate($key,$iv12,'',D($_[0]));
                                        my $p = chacha20poly1305_decrypt_verify($key,$iv12,'',$c,$t); \$p },
    'ccm one-shot ct'          => sub { my ($c,$t) = ccm_encrypt_authenticate('AES',$key,$n13,'',16,D($_[0])); \$c },
    'ccm one-shot pt'          => sub { my ($c,$t) = ccm_encrypt_authenticate('AES',$key,$n13,'',16,D($_[0]));
                                        my $p = ccm_decrypt_verify('AES',$key,$n13,'',$c,$t); \$p },
    'eax one-shot ct'          => sub { my ($c,$t) = eax_encrypt_authenticate('AES',$key,$iv12,'',D($_[0])); \$c },
    'eax one-shot pt'          => sub { my ($c,$t) = eax_encrypt_authenticate('AES',$key,$iv12,'',D($_[0]));
                                        my $p = eax_decrypt_verify('AES',$key,$iv12,'',$c,$t); \$p },
    'ocb one-shot ct'          => sub { my ($c,$t) = ocb_encrypt_authenticate('AES',$key,$iv12,'',16,D($_[0])); \$c },
    'ocb one-shot pt'          => sub { my ($c,$t) = ocb_encrypt_authenticate('AES',$key,$iv12,'',16,D($_[0]));
                                        my $p = ocb_decrypt_verify('AES',$key,$iv12,'',$c,$t); \$p },
    'siv one-shot ct'          => sub { my $c = siv_encrypt_authenticate('AES',$key,D($_[0]),''); \$c },
    'siv one-shot pt'          => sub { my $c = siv_encrypt_authenticate('AES',$key,D($_[0]),'');
                                        my $p = siv_decrypt_verify('AES',$key,$c,''); \$p },
    'gcm_siv one-shot ct'      => sub { my $c = gcm_siv_encrypt_authenticate('AES',$k16,$iv12,undef,D($_[0])); \$c },
    'gcm_siv one-shot pt'      => sub { my $c = gcm_siv_encrypt_authenticate('AES',$k16,$iv12,undef,D($_[0]));
                                        my $p = gcm_siv_decrypt_verify('AES',$k16,$iv12,undef,$c); \$p },
    'cipher block encrypt'     => sub { my $x = Crypt::Cipher->new('AES',$key)->encrypt('1234567890123456'); \$x },
    'cipher block decrypt'     => sub { my $x = Crypt::Cipher->new('AES',$key)->decrypt('1234567890123456'); \$x },
    'mode cbc add'             => sub { my $m = Crypt::Mode::CBC->new('AES');
                                        $m->start_encrypt($k16,$iv16);
                                        my $x = $m->add('1234567890123456' x (1 + $_[0] % 4)); \$x },
    'mode ctr add'             => sub { my $m = Crypt::Mode::CTR->new('AES');
                                        $m->start_encrypt($k16,$iv16); my $x = $m->add(D($_[0])); \$x },
    'mode xts encrypt'         => sub { my $x = Crypt::Mode::XTS->new('AES',$kxts)
                                          ->encrypt('1234567890123456' x (1 + $_[0] % 4), 2); \$x },
    'stream chacha crypt'      => sub { my $x = Crypt::Stream::ChaCha->new($key,$iv12)->crypt(D($_[0])); \$x },
    'stream chacha keystream'  => sub { my $x = Crypt::Stream::ChaCha->new($key,$iv12)->keystream($_[0]); \$x },
    'prng random_bytes'        => sub { my $x = random_bytes($_[0]); \$x },
    'prng random_bytes_hex'    => sub { my $x = Crypt::PRNG::random_bytes_hex($_[0]); \$x },
    'kdf pbkdf2'               => sub { my $x = pbkdf2('passwd','saltsalt',100,'SHA256',$_[0]); \$x },
    'kdf hkdf'                 => sub { my $x = hkdf($key,'saltsalt','SHA256',$_[0],'info'); \$x },
    'digest shake done'        => sub { my $x = Crypt::Digest::SHAKE->new(128)->add('data')->done($_[0]); \$x },
    'misc encode_b64'          => sub { my $x = encode_b64(D($_[0])); \$x },
    'misc decode_b64'          => sub { my $x = decode_b64(encode_b64(D($_[0]))); \$x },
    'misc increment_octets_be' => sub { my $x = increment_octets_be(D($_[0])); \$x },
    'control perl string'      => sub { my $x = '9' x $_[0]; \$x },
);

for my $name (sort keys %cases) {
    my $bad = 0;
    for my $i (1 .. 10) {
        my $len = 11 + (($i * 7) % 43);     # 11..53, varies per iteration
        poison();
        $bad++ if is_terminated($cases{$name}->($len)) != 1;
    }
    is($bad, 0, "$name: SV is NUL-terminated at SvCUR");
}

SKIP: {
    my $ok = eval {
        require Math::BigInt;
        Math::BigInt->VERSION('1.999808');
        Math::BigInt->import(lib => 'LTM');
        Math::BigInt->config('lib') eq 'Math::BigInt::LTM';
    };
    skip "Math::BigInt too old or LTM backend not selected", 1 unless $ok;
    my $bad = 0;
    for my $i (1 .. 10) {
        poison();
        my $x = Math::BigInt->new('1' . '2' x (11 + $i))->to_bytes;
        $bad++ if is_terminated(\$x) != 1;
    }
    is($bad, 0, "bigint LTM to_bytes: SV is NUL-terminated at SvCUR");
}
