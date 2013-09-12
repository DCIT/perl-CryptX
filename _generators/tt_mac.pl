use strict;
use warnings;

use Template;
use FindBin;
use Digest::SHA qw(sha1_hex);
use File::Slurp;
use File::Copy;
use File::Spec::Functions qw(catfile catdir abs2rel canonpath);
use Data::Dump 'pp';
use MIME::Base64 qw(encode_base64 encode_base64url);

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
        F9      => { info=>'Message authentication code F9', urls=>[] },
        HMAC    => { info=>'Message authentication code HMAC', urls=>['https://en.wikipedia.org/wiki/Hmac', 'https://tools.ietf.org/html/rfc2104'] },
        OMAC    => { info=>'Message authentication code OMAC', urls=>['https://en.wikipedia.org/wiki/OMAC_%28cryptography%29'] },
        Pelican => { info=>'Message authentication code Pelican (AES based MAC)', urls=>['http://eprint.iacr.org/2005/088.pdf'] },
        PMAC    => { info=>'Message authentication code PMAC', urls=>['https://en.wikipedia.org/wiki/PMAC_%28cryptography%29'] },
        XCBC    => { info=>'Message authentication code XCBC (RFC 3566)', urls=>['https://www.ietf.org/rfc/rfc3566.txt'] },
);

my @test_strings = ( '', '123', "test\0test\0test\n");

for my $n (keys %list) {
  warn "Processing mac: '$n'\n";
  my $data = {
    comment   => "### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!",
    orig_name => $n,
    uc_name   => uc($n),
    lc_name   => lc($n),
    info      => $list{$n}->{info},
    urls      => $list{$n}->{urls},
  };

  if($outdir_t) {
    require Crypt::Mac::HMAC;
    require Crypt::Mac::F9;
    require Crypt::Mac::OMAC;
    require Crypt::Mac::Pelican;
    require Crypt::Mac::PMAC;
    require Crypt::Mac::XCBC;

    for (@test_strings) {
      if ($n eq 'HMAC') {
        push @{$data->{t_strings}}, { mac=>unpack('H*', Crypt::Mac::HMAC->new('SHA1', 'secretkey')->add($_)->mac), data=>pp($_), args=>"'SHA1','secretkey'" };
        push @{$data->{t_strings}}, { mac=>unpack('H*', Crypt::Mac::HMAC->new('SHA512', 'secretkey')->add($_)->mac), data=>pp($_), args=>"'SHA512','secretkey'" };
        push @{$data->{t_strings}}, { mac=>unpack('H*', Crypt::Mac::HMAC->new('Tiger192', 'secretkey')->add($_)->mac), data=>pp($_), args=>"'Tiger192','secretkey'" };
        push @{$data->{t_strings}}, { mac=>unpack('H*', Crypt::Mac::HMAC->new('Whirlpool', 'secretkey')->add($_)->mac), data=>pp($_), args=>"'Whirlpool','secretkey'" };
      }
      elsif ($n eq 'Pelican') {
        push @{$data->{t_strings}}, { mac=>unpack('H*', Crypt::Mac::Pelican->new('1234567890123456')->add($_)->mac), data=>pp($_), args=>"'1234567890123456'" };
        push @{$data->{t_strings}}, { mac=>unpack('H*', Crypt::Mac::Pelican->new('12345678901234561234567890123456')->add($_)->mac), data=>pp($_), args=>"'12345678901234561234567890123456'" };
        push @{$data->{t_strings}}, { mac=>unpack('H*', Crypt::Mac::Pelican->new('aaaaaaaaaaaaaaaa')->add($_)->mac), data=>pp($_), args=>"'aaaaaaaaaaaaaaaa'" };
        push @{$data->{t_strings}}, { mac=>unpack('H*', Crypt::Mac::Pelican->new('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add($_)->mac), data=>pp($_), args=>"'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'" };
      }
      else {
        push @{$data->{t_strings}}, { mac=>unpack('H*', "Crypt::Mac::$n"->new('AES', '1234567890123456')->add($_)->mac), data=>pp($_), args=>"'AES','1234567890123456'" };
        push @{$data->{t_strings}}, { mac=>unpack('H*', "Crypt::Mac::$n"->new('AES', '12345678901234561234567890123456')->add($_)->mac), data=>pp($_), args=>"'AES','12345678901234561234567890123456'" };
        push @{$data->{t_strings}}, { mac=>unpack('H*', "Crypt::Mac::$n"->new('Blowfish', '1234567890123456')->add($_)->mac), data=>pp($_), args=>"'Blowfish','1234567890123456'" };
        push @{$data->{t_strings}}, { mac=>unpack('H*', "Crypt::Mac::$n"->new('Blowfish', '12345678901234561234567890123456')->add($_)->mac), data=>pp($_), args=>"'Blowfish','12345678901234561234567890123456'" };
      }
    }
    $_->{b64mac} = encode_base64(pack("H*", $_->{mac}),'') for (@{$data->{t_strings}});
    $_->{b64umac} = encode_base64url(pack("H*", $_->{mac}),'') for (@{$data->{t_strings}});
    $data->{t_strings_count} = defined $data->{t_strings} ? scalar(@{$data->{t_strings}}) : 0;

    my $t_out = catfile($outdir_t, "mac_".lc($n).".t");
    my $t_tt = Template->new(ABSOLUTE=>1) || die $Template::ERROR, "\n";
    $t_tt->process("$FindBin::Bin/Mac.t.tt", $data, "$t_out.$$") || die $t_tt->error(), "\n";
    copy("$t_out.$$", $t_out) and warn("Writting '$t_out'\n") unless equal_files("$t_out.$$", $t_out);
    unlink "$t_out.$$";
  }

  if ($outdir_l) {
    my $pm_out = catfile($outdir_l, "Crypt", "Mac", "$n.pm");
    my $pm_tt = Template->new(ABSOLUTE=>1) || die $Template::ERROR, "\n";
    $pm_tt->process("$FindBin::Bin/Mac.pm.tt", $data, "$pm_out.$$") || die $pm_tt->error(), "\n";
    copy("$pm_out.$$", $pm_out) and warn("Writting '$pm_out'\n") unless equal_files("$pm_out.$$", $pm_out);
    unlink "$pm_out.$$";

    my $xs_out = catfile($outdir_l, "CryptX_Mac_$n.xs.inc");
    my $xs_tt = Template->new(ABSOLUTE=>1) || die $Template::ERROR, "\n";
    $xs_tt->process("$FindBin::Bin/Mac.xs.inc.tt", $data, "$xs_out.$$") || die $xs_tt->error(), "\n";
    copy("$xs_out.$$", $xs_out) and warn("Writting '$xs_out'\n") unless equal_files("$xs_out.$$", $xs_out);
    unlink "$xs_out.$$";
  }

}