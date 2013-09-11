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
  my $d1 = sha1_hex(read_file(shift, binmode => ':raw'));
  my $d2 = sha1_hex(read_file(shift, binmode => ':raw'));
  return $d1 eq $d2;
}

die "No args given!\n" unless $ARGV[0];
my $outdir_l = ($ARGV[0] eq 'install_code')  ? catdir($FindBin::Bin, "..", "lib") : '';
my $outdir_t = ($ARGV[0] eq 'install_tests') ? catdir($FindBin::Bin, "..", "t")   : '';
warn "STARTED: outdir_l='$outdir_l' outdir_t='$outdir_t'\n";

my %list = (
        CHAES      => { ltc=>'chc_hash',  info=>'Hash function - CipherHash based on AES [size: 128 bits]', urls=>['http://en.wikipedia.org/wiki/Cryptographic_hash_function#Hash_functions_based_on_block_ciphers'] },
        MD2        => { ltc=>'md2',       info=>'Hash function MD2 [size: 128 bits]', urls=>['http://en.wikipedia.org/wiki/MD2_(cryptography)'] },
        MD4        => { ltc=>'md4',       info=>'Hash function MD4 [size: 128 bits]', urls=>['http://en.wikipedia.org/wiki/MD4'] },
        MD5        => { ltc=>'md5',       info=>'Hash function MD5 [size: 128 bits]', urls=>['http://en.wikipedia.org/wiki/MD5'] },
        RIPEMD128  => { ltc=>'rmd128',    info=>'Hash function RIPEMD-128 [size: 128 bits]', urls=>['http://en.wikipedia.org/wiki/RIPEMD'] },
        RIPEMD160  => { ltc=>'rmd160',    info=>'Hash function RIPEMD-160 [size: 160 bits]', urls=>['http://en.wikipedia.org/wiki/RIPEMD'] },
        RIPEMD256  => { ltc=>'rmd256',    info=>'Hash function RIPEMD-256 [size: 256 bits]', urls=>['http://en.wikipedia.org/wiki/RIPEMD'] },
        RIPEMD320  => { ltc=>'rmd320',    info=>'Hash function RIPEMD-320 [size: 320 bits]', urls=>['http://en.wikipedia.org/wiki/RIPEMD'] },
        SHA1       => { ltc=>'sha1',      info=>'Hash function SHA-1 [size: 160 bits]', urls=>['http://en.wikipedia.org/wiki/SHA-1'] },
        SHA224     => { ltc=>'sha224',    info=>'Hash function SHA-224 [size: 224 bits]', urls=>['http://en.wikipedia.org/wiki/SHA-2'] },
        SHA256     => { ltc=>'sha256',    info=>'Hash function SHA-256 [size: 256 bits]', urls=>['http://en.wikipedia.org/wiki/SHA-2'] },
        SHA384     => { ltc=>'sha384',    info=>'Hash function SHA-384 [size: 384 bits]', urls=>['http://en.wikipedia.org/wiki/SHA-2'] },
        SHA512     => { ltc=>'sha512',    info=>'Hash function SHA-512 [size: 512 bits]', urls=>['http://en.wikipedia.org/wiki/SHA-2'] },
        Tiger192   => { ltc=>'tiger',     info=>'Hash function Tiger-192 [size: 192 bits]', urls=>['http://en.wikipedia.org/wiki/Tiger_(cryptography)'] },
        Whirlpool  => { ltc=>'whirlpool', info=>'Hash function Whirlpool [size: 512 bits]', urls=>['http://en.wikipedia.org/wiki/Whirlpool_(cryptography)'] },
);

my @test_strings = ( '', '123', "test\0test\0test\n");
my @test_files = bsd_glob("$FindBin::Bin/../t/data/*.file");
@test_files = map { abs2rel(canonpath($_), canonpath("$FindBin::Bin/../")) } @test_files;

for my $n (keys %list) {
  warn "Processing digest: '$n'\n";
  
  my $data = {
    comment   => "### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!",
    orig_name => $n,
    uc_name   => uc($n),
    lc_name   => lc($n),
    ltc       => $list{$n}->{ltc},
    info      => $list{$n}->{info},
    desc      => $list{$n}->{desc},
    urls      => $list{$n}->{urls},
  };
  
  if ($outdir_t) {
    require Crypt::Digest;
    Crypt::Digest::import(':all');
    for (@test_strings) {
      push @{$data->{t_strings}}, { data=>pp($_), 
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

    my $t_out = catfile($outdir_t, "digest_".lc($n).".t");
    my $t_tt = Template->new(ABSOLUTE=>1) || die $Template::ERROR, "\n";
    $t_tt->process("$FindBin::Bin/Digest.t.tt", $data, "$t_out.$$") || die $t_tt->error(), "\n";
    copy("$t_out.$$", $t_out) and warn("Writting '$t_out'\n") unless equal_files("$t_out.$$", $t_out);
    unlink "$t_out.$$";
  }
  
  if ($outdir_l) {
    my $pm_out = catfile($outdir_l, "Crypt", "Digest", "$n.pm");
    my $pm_tt = Template->new(ABSOLUTE=>1) || die $Template::ERROR, "\n";
    $pm_tt->process("$FindBin::Bin/Digest.pm.tt", $data, $pm_out) || die $pm_tt->error(), "\n";
  }

}
