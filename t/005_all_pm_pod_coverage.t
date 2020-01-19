use strict;
use warnings;

use Test::More;

plan skip_all => "set AUTHOR_MODE to enable this test (developer only!)" unless $ENV{AUTHOR_MODE};
plan skip_all => "Pod::Coverage not installed" unless eval { require Pod::Coverage };
plan skip_all => "File::Find not installed" unless eval { require File::Find };
plan tests => 109;

my @files;
File::Find::find({ wanted=>sub { push @files, $_ if /\.pm$/ }, no_chdir=>1 }, 'lib');

my @err;
for my $m (sort @files) {
  my $f = $m;
  $m =~ s|[\\/]|::|g;
  $m =~ s|^lib::||;
  $m =~ s|\.pm$||;

  my $pc;
  if ($m eq 'Crypt::PK::DH') {
    $pc = Pod::Coverage->new(package => $m, pod_from => $f, trustme => [qr/^(decrypt|dh_decrypt|dh_encrypt|dh_sign_hash|dh_sign_message|dh_verify_hash|dh_verify_message|encrypt|sign_hash|sign_message|verify_hash|verify_message)$/] );
  }
  elsif ($m eq 'Math::BigInt::LTM') {
    $pc = Pod::Coverage->new(package => $m, pod_from => $f, trustme => [qr/^(STORABLE_thaw|STORABLE_freeze|api_version)$/] );
  }
  elsif ($m eq 'Crypt::Mode') {
    $pc = Pod::Coverage->new(package => $m, pod_from => $f, trustme => [qr/^(add|decrypt|encrypt|finish|new|start_decrypt|start_encrypt)$/] );
  }
  elsif ($m eq 'Crypt::Checksum') {
    $pc = Pod::Coverage->new(package => $m, pod_from => $f, trustme => [qr/^(addfile|(adler32_|crc32_)(file_hex|file_int|file|data_hex|data_int|data))$/] );
  }
  elsif ($m eq 'Crypt::Mac') {
    $pc = Pod::Coverage->new(package => $m, pod_from => $f, trustme => [qr/^(add|addfile)$/] );
  }
  elsif ($m =~ /^Crypt::Mode::(CTR|CFB|OFB)$/) {
    $pc = Pod::Coverage->new(package => $m, pod_from => $f, trustme => [qr/^(finish)$/] );
  }
  elsif ($m eq 'Crypt::AuthEnc::OCB') {
    $pc = Pod::Coverage->new(package => $m, pod_from => $f, trustme => [qr/^(blocksize|aad_add)$/] );
  }
  elsif ($m eq 'Crypt::AuthEnc::EAX') {
    $pc = Pod::Coverage->new(package => $m, pod_from => $f, trustme => [qr/^(header_add|aad_add)$/] );
  }
  else {
    $pc = Pod::Coverage->new(package => $m, pod_from => $f);
  }

  my $c = $pc->coverage || 0;
  my @u = $pc->uncovered;
  ok(@u == 0, sprintf("$m score=%.2f naked=(" . join(" ", @u) . ")", $c));
}
