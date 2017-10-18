use strict;
use warnings;

use Template;
use FindBin;
use Digest::SHA qw(sha1_hex);
use File::Slurp;
use File::Copy;
use File::Spec::Functions qw(catfile catdir abs2rel canonpath);

sub equal_files {
  my $d1 = sha1_hex(read_file(shift, binmode => ':raw'));
  my $d2 = sha1_hex(read_file(shift, binmode => ':raw'));
  return $d1 eq $d2;
}

die "No args given!\n" unless $ARGV[0];
my $outdir_l = ($ARGV[0] eq 'install_code')  ? catdir($FindBin::Bin, "..", "lib") : '';
my $outdir_i = ($ARGV[0] eq 'install_code')  ? catdir($FindBin::Bin, "..", "inc") : '';
my $outdir_t = ($ARGV[0] eq 'install_tests') ? catdir($FindBin::Bin, "..", "t")   : '';
warn "STARTED: outdir_l='$outdir_l' outdir_t='$outdir_t'\n";

my %list = (
        CBC => { info=>'Block cipher mode CBC [Cipher-block chaining]',
                 desc=>"This module implements CBC cipher mode. B<NOTE:> it works only with ciphers from L<CryptX> (Crypt::Cipher::NNNN).",
                 urls=>['https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29'],
               },
        CFB => { info=>'Block cipher mode CFB [Cipher feedback]',
                 desc=>"This module implements CFB cipher mode. B<NOTE:> it works only with ciphers from L<CryptX> (Crypt::Cipher::NNNN).",
                 urls=>['https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_.28CFB.29'],
               },
        CTR => { info=>'Block cipher mode CTR [Counter mode]',
                 desc=>"This module implements CTR cipher mode. B<NOTE:> it works only with ciphers from L<CryptX> (Crypt::Cipher::NNNN).",
                 urls=>['https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29'],
               },
        ECB => { info=>'Block cipher mode ECB [Electronic codebook]',
                 desc=>"This module implements ECB cipher mode. B<NOTE:> it works only with ciphers from L<CryptX> (Crypt::Cipher::NNNN).\n".
                       "B<BEWARE: ECB is inherently insecure>, if you are not sure go for L<Crypt::Mode::CBC>!",
                 urls=>['https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_.28ECB.29'],
               },
        OFB => { info=>'Block cipher mode OFB [Output feedback]',
                 desc=>"This module implements OFB cipher mode. B<NOTE:> it works only with ciphers from L<CryptX> (Crypt::Cipher::NNNN).",
                 urls=>['https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_.28OFB.29'],
               },
#        F8  => { info=>'Block cipher mode F8',
#                 desc=>q[xxx-desc-goes here]},
#        LRW => { info=>'Block cipher mode LRW [Liskov, Rivest, Wagner]',
#                 desc=>q[xxx-desc-goes here]},
#        XTS => { info=>'Block cipher mode XTS [XEX-based tweaked-codebook mode with ciphertext stealing]',
#                 desc=>q[xxx-desc-goes here]},
);

my ($pmver) = grep { /^our\s+\$VERSION/ } read_file("$FindBin::Bin/../lib/Crypt/Digest.pm");
$pmver =~ s/our\s+\$VERSION\s*=\s*'(.*?)'.*$/$1/s;

for my $n (keys %list) {
  warn "Processing mode: '$n'\n";

  my $data = {
    comment   => "### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!",
    pmver     => $pmver,
    orig_name => $n,
    uc_name   => uc($n),
    lc_name   => lc($n),
    info      => $list{$n}->{info},
    desc      => $list{$n}->{desc},
    urls      => $list{$n}->{urls},
  };

  if ($outdir_t) {
    #require Crypt::...

    #my $t_out = catfile($outdir_t, "mode_".lc($n).".t");
    #my $t_tt = Template->new(ABSOLUTE=>1) || die $Template::ERROR, "\n";
    #$t_tt->process("$FindBin::Bin/AuthEnc.t.tt", $data, "$t_out.$$", {binmode=>1}) || die $t_tt->error(), "\n";
    #copy("$t_out.$$", $t_out) and warn("Writting '$t_out'\n") unless equal_files("$t_out.$$", $t_out);
    #unlink "$t_out.$$";
  }

  if ($outdir_l && $outdir_i) {
    if (1) {  # if($n ne 'CBC' || $n ne 'ECB') {
      my $xs_out = catfile($outdir_i, "CryptX_Mode_$n.xs.inc");
      my $xs_tt = Template->new(ABSOLUTE=>1) || die $Template::ERROR, "\n";
      if ($n eq 'CBC' || $n eq 'ECB') {
        $xs_tt->process("$FindBin::Bin/Mode_p.xs.inc.tt", $data, "$xs_out.$$", {binmode=>1}) || die $xs_tt->error(), "\n";
      }
      else {
        $xs_tt->process("$FindBin::Bin/Mode.xs.inc.tt", $data, "$xs_out.$$", {binmode=>1}) || die $xs_tt->error(), "\n";
      }
      copy("$xs_out.$$", $xs_out) and warn("Writting '$xs_out'\n") unless equal_files("$xs_out.$$", $xs_out);
      unlink "$xs_out.$$";
    }

    my $pm_out = catfile($outdir_l, "Crypt", "Mode", "$n.pm");
    my $pm_tt = Template->new(ABSOLUTE=>1) || die $Template::ERROR, "\n";
    $pm_tt->process("$FindBin::Bin/Mode.pm.tt", $data, "$pm_out.$$", {binmode=>1}) || die $pm_tt->error(), "\n";
    copy("$pm_out.$$", $pm_out) and warn("Writting '$pm_out'\n") unless equal_files("$pm_out.$$", $pm_out);
    unlink "$pm_out.$$";
  }
}
