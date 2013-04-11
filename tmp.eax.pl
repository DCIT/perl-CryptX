use CryptX::AuthEnc::EAX;
use strict;
use warnings;

my $nonce = "yy";

my $key = "12345678901234561234567890123456";

my $pt1 = "123123123123123123123123123123123123123";
my $m1 = CryptX::AuthEnc::EAX->new("AES", $key, $nonce);
$m1->header_add("a");
$m1->header_add("b");
my $ct1 = $m1->encrypt_add($pt1);
my $tg1 = $m1->encrypt_done;

warn "B.pt1=$pt1\n";
warn "A.ct1=", unpack('H*', $ct1), "\n";
warn "A.len=", length($tg1), " tag=", unpack('H*', $tg1), "\n";


my $m2 = CryptX::AuthEnc::EAX->new("AES", $key, $nonce);
$m2->header_add("ab");
my $pt2 = $m2->decrypt_add($ct1);
my $tg2 = $m2->decrypt_done($tg1);

warn "B.pt2=$pt2\n";
warn "B.tg2=$tg2\n";
warn "B.len=", length($tg2), " tag=", unpack('H*', $tg2), "\n";

