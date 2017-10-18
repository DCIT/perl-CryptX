use strict;
use warnings;

use Template;
use FindBin;
use Digest::SHA qw(sha1_hex);
use File::Slurp;
use File::Copy;
use File::Spec::Functions qw(catfile catdir abs2rel canonpath);

sub equal_files {
  my ($f1, $f2) = @_;
  return unless -f $f1 && -f $f2;
  my $d1 = sha1_hex(read_file($f1, binmode => ':raw'));
  my $d2 = sha1_hex(read_file($f2, binmode => ':raw'));
  return $d1 eq $d2;
}

die "No args given!\n" unless $ARGV[0];
my $outdir_l = ($ARGV[0] eq 'install_code')  ? catdir($FindBin::Bin, "..", "lib") : '';
my $outdir_t = ($ARGV[0] eq 'install_tests') ? catdir($FindBin::Bin, "..", "t")   : '';
warn "STARTED: outdir_l='$outdir_l' outdir_t='$outdir_t'\n";

my %list = (
        AES         => { info=>'Symetric cipher AES (aka Rijndael), key size: 128/192/256 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/Advanced_Encryption_Standard'],
                         spec_rounds=>0, spec_key=>'XXX-DETERMINED-BY-KEYSIZE' },
        Anubis      => { info=>'Symetric cipher Anubis, key size: 128-320 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/Anubis_(cipher)'],
                         spec_rounds=>0, spec_key=>'XXX-DETERMINED-BY-KEYSIZE' },
        Blowfish    => { info=>'Symetric cipher Blowfish, key size: 64-448 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/Blowfish_(cipher)'],
                         spec_rounds=>0, spec_key=>'XXX-ROUNDS-FIXED' },
        CAST5       => { info=>'Symetric cipher CAST5 (aka CAST-128), key size: 40-128 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/CAST-128'],
                         spec_rounds=>0, spec_key=>'XXX-DETERMINED-BY-KEYSIZE' }, # 12 (<=80bits), 16 (>80bits)
        DES         => { info=>'Symetric cipher DES, key size: 64[56] bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/Data_Encryption_Standard'],
                         spec_rounds=>0, spec_key=>'XXX-ROUNDS-FIXED' },
        DES_EDE     => { info=>'Symetric cipher DES_EDE (aka Tripple-DES, 3DES), key size: 192[168] bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/Triple_DES'],
                         spec_rounds=>0, spec_key=>'XXX-ROUNDS-FIXED' },
        KASUMI      => { info=>'Symetric cipher KASUMI, key size: 128 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/KASUMI_(block_cipher)'],
                         spec_rounds=>0, spec_key=>'XXX-ROUNDS-FIXED' },
        Khazad      => { info=>'Symetric cipher Khazad, key size: 128 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/KHAZAD'],
                         spec_rounds=>0, spec_key=>'XXX-ROUNDS-FIXED' },
        MULTI2      => { info=>'Symetric cipher MULTI2, key size: 320 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/MULTI2'],
                         spec_rounds=>199, spec_key=>'S' x 40 }, # default = 128, no-limits!
        Noekeon     => { info=>'Symetric cipher Noekeon, key size: 128 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/NOEKEON'],
                         spec_rounds=>0, spec_key=>'XXX-ROUNDS-FIXED' },
        RC2         => { info=>'Symetric cipher RC2, key size: 40-1024 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/RC2'],
                         spec_rounds=>0, spec_key=>'XXX-ROUNDS-FIXED' },
        RC5         => { info=>'Symetric cipher RC5, key size: 64-1024 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/RC5'],
                         spec_rounds=>19, spec_key=>'S' x 100 }, # 12..24
        RC6         => { info=>'Symetric cipher RC6, key size: 64-1024 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/RC6'],
                         spec_rounds=>0, spec_key=>'XXX-ROUNDS-FIXED' },
        SAFERP      => { info=>'Symetric cipher SAFER+, key size: 128/192/256 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/SAFER'],
                         spec_rounds=>0, spec_key=>'XXX-DETERMINED-BY-KEYSIZE' },
        SAFER_K128  => { info=>'Symetric cipher SAFER_K128, key size: 128 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/SAFER'],
                         spec_rounds=>11, spec_key=>'S' x 16 }, # 6..13
        SAFER_K64   => { info=>'Symetric cipher SAFER_K64, key size: 64 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/SAFER'],
                         spec_rounds=>9, spec_key=>'S' x 8 }, # 6..13
        SAFER_SK128 => { info=>'Symetric cipher SAFER_SK128, key size: 128 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/SAFER'],
                         spec_rounds=>11, spec_key=>'S' x 16 }, # 6..13
        SAFER_SK64  => { info=>'Symetric cipher SAFER_SK64, key size: 64 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/SAFER'],
                         spec_rounds=>9, spec_key=>'S' x 8 }, # 6..13
        SEED        => { info=>'Symetric cipher SEED, key size: 128 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/SEED'],
                         spec_rounds=>0, spec_key=>'XXX-ROUNDS-FIXED' },
        Skipjack    => { info=>'Symetric cipher Skipjack, key size: 80 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/Skipjack_(cipher)'],
                         spec_rounds=>0, spec_key=>'XXX-ROUNDS-FIXED' },
        Twofish     => { info=>'Symetric cipher Twofish, key size: 128/192/256 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/Twofish'],
                         spec_rounds=>0, spec_key=>'XXX-ROUNDS-FIXED' },
        XTEA        => { info=>'Symetric cipher XTEA, key size: 128 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/XTEA'],
                         spec_rounds=>0, spec_key=>'XXX-ROUNDS-FIXED' },
        Camellia    => { info=>'Symetric cipher Camellia, key size: 128/192/256 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/Camellia_(cipher)'],
                         spec_rounds=>0, spec_key=>'XXX-DETERMINED-BY-KEYSIZE' },
        IDEA        => { info=>'Symetric cipher IDEA, key size: 128 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm'],
                         spec_rounds=>0, spec_key=>'XXX-ROUNDS-FIXED' },
        Serpent     => { info=>'Symetric cipher Serpent, key size: 128/192/256 bits (Crypt::CBC compliant)', urls=>['http://en.wikipedia.org/wiki/Serpent_(cipher)'],
                         spec_rounds=>0, spec_key=>'XXX-ROUNDS-FIXED' },
);

my ($pmver) = grep { /^our\s+\$VERSION/ } read_file("$FindBin::Bin/../lib/Crypt/Digest.pm");
$pmver =~ s/our\s+\$VERSION\s*=\s*'(.*?)'.*$/$1/s;

for my $n (keys %list) {
  warn "Processing cipher: '$n'\n";

  my $data = {
    %{$list{$n}},
    comment   => "### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!",
    pmver     => $pmver,
    orig_name => $n,
    uc_name   => uc($n),
    lc_name   => lc($n),
  };

  if ($outdir_t) {
    require Crypt::Cipher;
    $data->{blocksize} = Crypt::Cipher->blocksize($n);
    $data->{keysize} = Crypt::Cipher->keysize($n);
    $data->{max_keysize} = Crypt::Cipher->max_keysize($n);
    $data->{min_keysize} = Crypt::Cipher->min_keysize($n);
    $data->{default_rounds} = Crypt::Cipher->default_rounds($n);
    $data->{min_key} = 'k' x $data->{min_keysize};
    $data->{max_key} = 'K' x $data->{max_keysize};
    $data->{block_plain} = 'B' x $data->{blocksize};
    $data->{block_encrypted_min_key_hex} = unpack('H*', Crypt::Cipher->new($n, $data->{min_key})->encrypt($data->{block_plain}));
    $data->{block_encrypted_max_key_hex} = unpack('H*', Crypt::Cipher->new($n, $data->{max_key})->encrypt($data->{block_plain}));
    if ($data->{spec_rounds}) {
      $data->{spec_block_encrypted_hex} = unpack('H*', Crypt::Cipher->new($n, $data->{spec_key}, $data->{spec_rounds})->encrypt($data->{block_plain}));
    }

    my $t_out = catfile($outdir_t, "cipher_".lc($n).".t");
    my $t_tt = Template->new(ABSOLUTE=>1) || die $Template::ERROR, "\n";
    $t_tt->process("$FindBin::Bin/Cipher.t.tt", $data, "$t_out.$$", {binmode=>1}) || die $t_tt->error(), "\n";
    copy("$t_out.$$", $t_out) and warn("Writting '$t_out'\n") unless equal_files("$t_out.$$", $t_out);
    unlink "$t_out.$$";
  }

  if ($outdir_l) {
    my $pm_out = catfile($outdir_l, "Crypt", "Cipher", "$n.pm");
    my $pm_tt = Template->new(ABSOLUTE=>1) || die $Template::ERROR, "\n";
    $pm_tt->process("$FindBin::Bin/Cipher.pm.tt", $data, "$pm_out.$$", {binmode=>1}) || die $pm_tt->error(), "\n";
    copy("$pm_out.$$", $pm_out) and warn("Writting '$pm_out'\n") unless equal_files("$pm_out.$$", $pm_out);
    unlink "$pm_out.$$";
  }

}
