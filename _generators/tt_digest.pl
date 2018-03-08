use strict;
use warnings;

use Template;
use FindBin;
use Digest::SHA qw(sha1_hex);
use File::Slurp;
use File::Copy;
use File::Spec::Functions qw(catfile catdir abs2rel canonpath);
use Data::Dump 'pp';
use File::Glob qw(bsd_glob);

sub equal_files {
  return 0 unless -f $_[0] && -f $_[1];
  my $d1 = sha1_hex(read_file(shift, binmode => ':raw'));
  my $d2 = sha1_hex(read_file(shift, binmode => ':raw'));
  return $d1 eq $d2;
}

die "No args given!\n" unless $ARGV[0];
my $outdir_l = ($ARGV[0] eq 'install_code')  ? catdir($FindBin::Bin, "..", "lib") : '';
my $outdir_t = ($ARGV[0] eq 'install_tests') ? catdir($FindBin::Bin, "..", "t")   : '';
warn "STARTED: outdir_l='$outdir_l' outdir_t='$outdir_t'\n";

my %list = (
        CHAES       => { ltc=>'chc_hash',    info=>'Hash function - CipherHash based on AES [size: 128 bits]', urls=>['https://en.wikipedia.org/wiki/Cryptographic_hash_function#Hash_functions_based_on_block_ciphers'] },
        MD2         => { ltc=>'md2',         info=>'Hash function MD2 [size: 128 bits]', urls=>['https://en.wikipedia.org/wiki/MD2_(cryptography)'] },
        MD4         => { ltc=>'md4',         info=>'Hash function MD4 [size: 128 bits]', urls=>['https://en.wikipedia.org/wiki/MD4'] },
        MD5         => { ltc=>'md5',         info=>'Hash function MD5 [size: 128 bits]', urls=>['https://en.wikipedia.org/wiki/MD5'] },
        RIPEMD128   => { ltc=>'rmd128',      info=>'Hash function RIPEMD-128 [size: 128 bits]', urls=>['https://en.wikipedia.org/wiki/RIPEMD'] },
        RIPEMD160   => { ltc=>'rmd160',      info=>'Hash function RIPEMD-160 [size: 160 bits]', urls=>['https://en.wikipedia.org/wiki/RIPEMD'] },
        RIPEMD256   => { ltc=>'rmd256',      info=>'Hash function RIPEMD-256 [size: 256 bits]', urls=>['https://en.wikipedia.org/wiki/RIPEMD'] },
        RIPEMD320   => { ltc=>'rmd320',      info=>'Hash function RIPEMD-320 [size: 320 bits]', urls=>['https://en.wikipedia.org/wiki/RIPEMD'] },
        SHA1        => { ltc=>'sha1',        info=>'Hash function SHA-1 [size: 160 bits]', urls=>['https://en.wikipedia.org/wiki/SHA-1'] },
        SHA224      => { ltc=>'sha224',      info=>'Hash function SHA-224 [size: 224 bits]', urls=>['https://en.wikipedia.org/wiki/SHA-2'] },
        SHA256      => { ltc=>'sha256',      info=>'Hash function SHA-256 [size: 256 bits]', urls=>['https://en.wikipedia.org/wiki/SHA-2'] },
        SHA384      => { ltc=>'sha384',      info=>'Hash function SHA-384 [size: 384 bits]', urls=>['https://en.wikipedia.org/wiki/SHA-2'] },
        SHA512      => { ltc=>'sha512',      info=>'Hash function SHA-512 [size: 512 bits]', urls=>['https://en.wikipedia.org/wiki/SHA-2'] },
        SHA512_224  => { ltc=>'sha512_224',  info=>'Hash function SHA-512/224 [size: 224 bits]', urls=>['https://en.wikipedia.org/wiki/SHA-2'] },
        SHA512_256  => { ltc=>'sha512_256',  info=>'Hash function SHA-512/256 [size: 256 bits]', urls=>['https://en.wikipedia.org/wiki/SHA-2'] },
        SHA3_224    => { ltc=>'sha3-224',    info=>'Hash function SHA3-224 [size: 224 bits]', urls=>['https://en.wikipedia.org/wiki/SHA-3'] },
        SHA3_256    => { ltc=>'sha3-256',    info=>'Hash function SHA3-256 [size: 256 bits]', urls=>['https://en.wikipedia.org/wiki/SHA-3'] },
        SHA3_384    => { ltc=>'sha3-384',    info=>'Hash function SHA3-384 [size: 384 bits]', urls=>['https://en.wikipedia.org/wiki/SHA-3'] },
        SHA3_512    => { ltc=>'sha3-512',    info=>'Hash function SHA3-512 [size: 512 bits]', urls=>['https://en.wikipedia.org/wiki/SHA-3'] },
        Keccak224   => { ltc=>'keccak224',   info=>'Hash function Keccak-224 [size: 224 bits]', urls=>['https://keccak.team/index.html'] },
        Keccak256   => { ltc=>'keccak256',   info=>'Hash function Keccak-256 [size: 256 bits]', urls=>['https://keccak.team/index.html'] },
        Keccak384   => { ltc=>'keccak384',   info=>'Hash function Keccak-384 [size: 384 bits]', urls=>['https://keccak.team/index.html'] },
        Keccak512   => { ltc=>'keccak512',   info=>'Hash function Keccak-512 [size: 512 bits]', urls=>['https://keccak.team/index.html'] },
        Tiger192    => { ltc=>'tiger',       info=>'Hash function Tiger-192 [size: 192 bits]', urls=>['https://en.wikipedia.org/wiki/Tiger_(cryptography)'] },
        Whirlpool   => { ltc=>'whirlpool',   info=>'Hash function Whirlpool [size: 512 bits]', urls=>['https://en.wikipedia.org/wiki/Whirlpool_(cryptography)'] },
        BLAKE2b_160 => { ltc=>'blake2b-160', info=>'Hash function BLAKE2b [size: 160 bits]', urls=>['https://blake2.net/', 'https://tools.ietf.org/html/rfc7693'] },
        BLAKE2b_256 => { ltc=>'blake2b-256', info=>'Hash function BLAKE2b [size: 256 bits]', urls=>['https://blake2.net/', 'https://tools.ietf.org/html/rfc7693'] },
        BLAKE2b_384 => { ltc=>'blake2b-384', info=>'Hash function BLAKE2b [size: 384 bits]', urls=>['https://blake2.net/', 'https://tools.ietf.org/html/rfc7693'] },
        BLAKE2b_512 => { ltc=>'blake2b-512', info=>'Hash function BLAKE2b [size: 512 bits]', urls=>['https://blake2.net/', 'https://tools.ietf.org/html/rfc7693'] },
        BLAKE2s_128 => { ltc=>'blake2s-128', info=>'Hash function BLAKE2s [size: 128 bits]', urls=>['https://blake2.net/', 'https://tools.ietf.org/html/rfc7693'] },
        BLAKE2s_160 => { ltc=>'blake2s-160', info=>'Hash function BLAKE2s [size: 160 bits]', urls=>['https://blake2.net/', 'https://tools.ietf.org/html/rfc7693'] },
        BLAKE2s_224 => { ltc=>'blake2s-224', info=>'Hash function BLAKE2s [size: 224 bits]', urls=>['https://blake2.net/', 'https://tools.ietf.org/html/rfc7693'] },
        BLAKE2s_256 => { ltc=>'blake2s-256', info=>'Hash function BLAKE2s [size: 256 bits]', urls=>['https://blake2.net/', 'https://tools.ietf.org/html/rfc7693'] },
);

my @test_strings = ( '', '123', "test\0test\0test\n");
my @test_files = bsd_glob("$FindBin::Bin/../t/data/*.file");
@test_files = map { abs2rel(canonpath($_), canonpath("$FindBin::Bin/../")) } @test_files;

my ($pmver) = grep { /^our\s+\$VERSION/ } read_file("$FindBin::Bin/../lib/Crypt/Digest.pm");
$pmver =~ s/our\s+\$VERSION\s*=\s*'(.*?)'.*$/$1/s;

for my $n (sort keys %list) {
  warn "Processing digest: '$n'\n";

  my $data = {
    comment   => "### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!",
    pmver     => $pmver,
    orig_name => $n,
    uc_name   => uc($n),
    lc_name   => lc($n),
    ltc       => $list{$n}->{ltc},
    info      => $list{$n}->{info},
    desc      => $list{$n}->{desc},
    urls      => $list{$n}->{urls},
  };

  if ($outdir_t) {
    eval "use Crypt::Digest ':all';"; die $@ if $@;
    #require Crypt::Digest;
    #Crypt::Digest::import(':all');
    for (@test_strings) {
      my $d = pp($_);
      $d = "\"$d\"" if $d =~ /^\d*$/; # 123 >>> "123"
      push @{$data->{t_strings}}, { data=>$d,
                                    hex=>Crypt::Digest::digest_data_hex($n, $_),
                                    base64=>Crypt::Digest::digest_data_b64($n, $_),
                                    base64url=>Crypt::Digest::digest_data_b64u($n, $_),
                                  };
    }
    for (@test_files) {
      $_ =~ s|\\|/|g;
      push @{$data->{t_files}}, { file=>$_,
                                  hex=>Crypt::Digest::digest_file_hex($n, "$FindBin::Bin/../$_"),
                                  base64=>Crypt::Digest::digest_file_b64($n, "$FindBin::Bin/../$_"),
                                  base64url=>Crypt::Digest::digest_file_b64u($n, "$FindBin::Bin/../$_"),
                                };
    }
    $data->{t_files_count} = scalar(@{$data->{t_files}});
    $data->{t_strings_count} = scalar(@{$data->{t_strings}});
    $data->{hashsize} = Crypt::Digest->hashsize($n);
    $data->{tripple_A} = { 
                           hex       => Crypt::Digest::digest_data_hex($n, "AAA"),
                           base64    => Crypt::Digest::digest_data_b64($n, "AAA"),
                           base64url => Crypt::Digest::digest_data_b64u($n, "AAA"),
                         };

    my $t_out = catfile($outdir_t, "digest_".lc($n).".t");
    my $t_tt = Template->new(ABSOLUTE=>1) || die $Template::ERROR, "\n";
    $t_tt->process("$FindBin::Bin/Digest.t.tt", $data, "$t_out.$$", {binmode=>1}) || die $t_tt->error(), "\n";
    copy("$t_out.$$", $t_out) and warn("Writting '$t_out'\n") unless equal_files("$t_out.$$", $t_out);
    unlink "$t_out.$$";
  }

  if ($outdir_l) {
    my $pm_out = catfile($outdir_l, "Crypt", "Digest", "$n.pm");
    my $pm_tt = Template->new(ABSOLUTE=>1) || die $Template::ERROR, "\n";
    $pm_tt->process("$FindBin::Bin/Digest.pm.tt", $data, $pm_out, {binmode=>1}) || die $pm_tt->error(), "\n";
  }

}
