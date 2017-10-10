use strict;
use warnings;

use Crypt::Misc qw(read_rawfile write_rawfile encode_b64 decode_b64);
use Crypt::PK::RSA;
use Test::More;

sub test_rsa { # copy from pk_rsa_test_vectors_openssl.t
  my $h = shift;
  my $rsa_pri = Crypt::PK::RSA->new->import_key(\decode_b64($h->{PRIDER}));
  my $rsa_pub = Crypt::PK::RSA->new->import_key(\decode_b64($h->{PUBDER}));
  my $rsa_pri_h = $rsa_pri->key2hash;
  my $rsa_pub_h = $rsa_pub->key2hash;
  is($rsa_pri_h->{d}, $h->{PRI}, "$h->{ID}/PRI");
  is($rsa_pri_h->{N}, $h->{PUB}, "$h->{ID}/PUB");
  is($rsa_pub_h->{N}, $h->{PUB}, "$h->{ID}/PUB");
  is( $rsa_pri->decrypt(decode_b64($h->{ENC}), 'v1.5'), 'test-data', "$h->{ID}/ENC") || return 0;
  ok( $rsa_pub->verify_message(decode_b64($h->{SIGSHA1}),   'test-data', 'SHA1',   'v1.5'), "$h->{ID}/SIGSHA1")   || return 0;
  ok( $rsa_pub->verify_message(decode_b64($h->{SIGSHA256}), 'test-data', 'SHA256', 'v1.5'), "$h->{ID}/SIGSHA256") || return 0;
  return 1 if !$h->{SIGSHA512}; #SHA512 might be too big for short RSA keys
  ok( $rsa_pub->verify_message(decode_b64($h->{SIGSHA512}), 'test-data', 'SHA512', 'v1.5'), "$h->{ID}/SIGSHA512") || return 0;
  return 1;
}

write_rawfile("input.data", "test-data");
open(my $outfh, ">", "rsa_tmp.$$.txt") or die "cannot open";
my $ver = `openssl version` =~ s/[\r\n]*$//r;
print $outfh "my \$data = [ #test vectors generated by: $ver\n";
for my $I (1..10000) {
  for my $C (qw(512 1024 1536 2048 3072 4096)) {
    my $ID="key-$C-$I";
    my $PREF="$ID-$$";
    warn "######## processing $PREF\n";
    system("openssl genrsa -out $PREF.key.pem $C");
    system("openssl rsa -in $PREF.key.pem -out $PREF.priv.pem");
    system("openssl rsa -in $PREF.key.pem -pubout -out $PREF.pub.pem");
    system("openssl rsa -in $PREF.key.pem -out $PREF.priv.der -outform der");
    system("openssl rsa -in $PREF.key.pem -pubout -out $PREF.pub.der -outform der");
    system("openssl dgst -sha1   -sign $PREF.priv.pem -out $PREF.sha1.sig input.data");
    system("openssl dgst -sha256 -sign $PREF.priv.pem -out $PREF.sha256.sig input.data");
    system("openssl dgst -sha512 -sign $PREF.priv.pem -out $PREF.sha512.sig input.data");
    system("openssl rsautl -encrypt -inkey $PREF.pub.pem -pubin -out $PREF.enc -in input.data");
    my $PRI_DER    = encode_b64(read_rawfile("$PREF.priv.der"));
    my $PUB_DER    = encode_b64(read_rawfile("$PREF.pub.der"));
    my $SIG_SHA1   = encode_b64(read_rawfile("$PREF.sha1.sig"));
    my $SIG_SHA256 = encode_b64(read_rawfile("$PREF.sha256.sig"));
    my $SIG_SHA512 = encode_b64(read_rawfile("$PREF.sha512.sig"));
    my $ENCRYPTED  = encode_b64(read_rawfile("$PREF.enc"));
    my @key_dump = split /[\r\n]+/, `openssl rsa -in "$PREF.priv.pem" -inform PEM -text` =~ s/:[\r\n]+ +/:/sgr;
    my %h = map { my ($k, $v) = /^([a-zA-Z0-9]+):(.*)/; ($k||0)=>($v||0) =~ s/[: ]//sgr } @key_dump; # ugly, I know
    my $PRI = uc $h{privateExponent} =~ s/^0+//r;
    my $PUB = uc $h{modulus} =~ s/^0+//r;
    print $outfh "  {ID=>'$ID',SIZE=>$C,PRI=>'$PRI',PUB=>'$PUB',SIGSHA1=>'$SIG_SHA1',SIGSHA256=>'$SIG_SHA256',SIGSHA512=>'$SIG_SHA512',ENC=>'$ENCRYPTED',PRIDER=>'$PRI_DER',PUBDER=>'$PUB_DER'},\n";
    test_rsa({ID=>$ID,SIZE=>$C,PRI=>$PRI,PUB=>$PUB,SIGSHA1=>$SIG_SHA1,SIGSHA256=>$SIG_SHA256,SIGSHA512=>$SIG_SHA512,ENC=>$ENCRYPTED,PRIDER=>$PRI_DER,PUBDER=>$PUB_DER}) || die;
    unlink "$PREF.key.pem";
    unlink "$PREF.priv.pem";
    unlink "$PREF.pub.pem";
    unlink "$PREF.priv.der";
    unlink "$PREF.pub.der";
    unlink "$PREF.sha1.sig";
    unlink "$PREF.sha256.sig";
    unlink "$PREF.sha512.sig";
  }
}
print $outfh "];\n";
