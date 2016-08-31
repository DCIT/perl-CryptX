use strict;
use warnings;

use Template;
use FindBin;
use File::Spec::Functions qw(catfile catdir splitpath);
use File::Slurp;
use File::Find qw(find);

sub replace_text {
  my ($dir, $oldstring, $newstring) = @_;
  my @files;
  warn "replace: '$oldstring' > '$newstring'\n";
  find({ wanted=>sub { push @files, $_ if /\.c$/ }, no_chdir=>1 }, $dir);
  #warn "replace: count=",scalar(@files),"\n";
  for my $m (sort @files) {
    my $txt1 = read_file($m, binmode => ':utf8');
    my $txt2 = $txt1;
    $txt2 =~ s/\Q$oldstring\E/$newstring/g;
    warn "write_file $m" if $txt1 ne $txt2;
    write_file($m, {binmode => ':utf8'}, $txt2) if $txt1 ne $txt2;
  }
}

sub remove_files {
  my ($dir, $re) = @_;
  my @files;
  find({ wanted=>sub { push @files, $_ }, no_chdir=>1 }, $dir);
  for my $m (sort @files) {
    warn "unlink $m" if $m =~ $re;
    unlink $m if $m =~ $re;
  }
}

### MAIN

my $srcdir = catdir($FindBin::Bin, "..", "src/ltc");

my @lines = read_file("$srcdir/headers/tomcrypt_custom.h");
@lines = map { s|^([\t\s]*)#define LTC_NO_PROTOTYPES|$1/* #define LTC_NO_PROTOTYPES */|; $_ } @lines;
write_file("$srcdir/headers/tomcrypt_custom.h", {binmode => ':raw'}, @lines);

my @rename2inc = (qw[
        ciphers/aes/aes_tab.c
        ciphers/twofish/twofish_tab.c
        ciphers/safer/safer_tab.c
        hashes/whirl/whirltab.c
        prngs/sober128tab.c
]);

for my $f (@rename2inc) {
  my $src = catfile($srcdir, $f);
  warn "FATAL: non-existing file '$src'" and next unless -f $src;
  my (undef, undef, $file) = File::Spec->splitpath($src);
  my $dst = "$src.inc";
  rename($src, $dst);
  replace_text($srcdir, "$file\"", "$file.inc\"");
}

remove_files($srcdir, qr/_test\.c$/);
remove_files($srcdir, qr/f8_test_mode\.c$/);
remove_files($srcdir, qr/gmp_desc\.c$/);
remove_files($srcdir, qr/tfm_desc\.c$/);
remove_files("$srcdir/encauth/ocb", qr/.*/);
