use strict;
use warnings;
use Test::More tests => 14;

use Crypt::PK::RSA;
use Crypt::PK::ECC;

### generating test keys:
#
# openssl genrsa -out rsakey.priv.pem 1024
# openssl.exe pkcs8 -topk8 -v1 PBE-SHA1-3DES -passout pass:secret -in rsakey.priv.pem -out pkcs8.rsa-priv-pass.pem
# openssl.exe pkcs8 -topk8 -v1 PBE-SHA1-3DES -passout pass:secret -in rsakey.priv.pem -out pkcs8.rsa-priv-pass.der -outform DER
# openssl.exe pkcs8 -topk8 -nocrypt -in rsakey.priv.pem -out pkcs8.rsa-priv-nopass.pem
# openssl.exe pkcs8 -topk8 -nocrypt -in rsakey.priv.pem -out pkcs8.rsa-priv-nopass.der  -outform DER
#
# openssl ecparam -param_enc explicit -name prime192v3 -genkey -out eckey.priv.pem
# openssl.exe pkcs8 -topk8 -v1 PBE-SHA1-3DES -passout pass:secret -in eckey.priv.pem -out pkcs8.ec-priv-pass.pem
# openssl.exe pkcs8 -topk8 -v1 PBE-SHA1-3DES -passout pass:secret -in eckey.priv.pem -out pkcs8.ec-priv-pass.der -outform DER
# openssl.exe pkcs8 -topk8 -nocrypt -in eckey.priv.pem -out pkcs8.ec-priv-nopass.pem
# openssl.exe pkcs8 -topk8 -nocrypt -in eckey.priv.pem -out pkcs8.ec-priv-nopass.der  -outform DER
#
# openssl ecparam -name prime192v3 -genkey -out eckey.priv.pem
# openssl.exe pkcs8 -topk8 -v1 PBE-SHA1-3DES -passout pass:secret -in eckey.priv.pem -out pkcs8.ec-short-priv-pass.pem
# openssl.exe pkcs8 -topk8 -v1 PBE-SHA1-3DES -passout pass:secret -in eckey.priv.pem -out pkcs8.ec-short-priv-pass.der -outform DER
# openssl.exe pkcs8 -topk8 -nocrypt -in eckey.priv.pem -out pkcs8.ec-short-priv-nopass.pem
# openssl.exe pkcs8 -topk8 -nocrypt -in eckey.priv.pem -out pkcs8.ec-short-priv-nopass.der  -outform DER
#

my $rsa = Crypt::PK::RSA->new;
my $ec  = Crypt::PK::ECC->new;
ok($rsa, "RSA new");
ok($ec,  "ECC new");

for my $f (qw/pkcs8.rsa-priv-nopass.pem pkcs8.rsa-priv-nopass.der/) {
  $rsa->import_key("t/data/$f");
  ok($rsa->is_private, "RSA is_private $f");
}

for my $f (qw/pkcs8.rsa-priv-pass.der pkcs8.rsa-priv-pass.pem/) {
  $rsa->import_key("t/data/$f", "secret");
  ok($rsa->is_private, "RSA is_private $f");
}

for my $f (qw/pkcs8.ec-short-priv-nopass.der pkcs8.ec-short-priv-nopass.pem pkcs8.ec-priv-nopass.der pkcs8.ec-priv-nopass.pem/) {
  $ec->import_key("t/data/$f");
  ok($ec->is_private, "ECC is_private $f");
}

for my $f (qw/pkcs8.ec-priv-pass.der pkcs8.ec-priv-pass.pem pkcs8.ec-short-priv-pass.der pkcs8.ec-short-priv-pass.pem/) {
  $ec->import_key("t/data/$f", "secret");
  ok($ec->is_private, "ECC is_private $f (pw)");
}
