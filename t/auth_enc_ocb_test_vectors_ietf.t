use strict;
use warnings;

use Test::More tests => 48;
use Crypt::AuthEnc::OCB;

my $count = 1;
my $d = {};
my $text;

while (my $l = <DATA>) {
  chomp($l);
  next if $l =~ /^#/;
  $l =~ s/[\s\t]+/ /g;
  
  if ($l eq '') {
    next unless defined $d->{C};
    my $K = pack('H*', '000102030405060708090A0B0C0D0E0F');
    my $N = pack('H*', '000102030405060708090A0B');
    my $A = pack('H*', $d->{A});
    my $P = pack('H*', $d->{P});
    my $C = pack('H*', $d->{C});
    
    { #ENCRYPT
      my $m = Crypt::AuthEnc::OCB->new('AES', $K, $N);
      $m->adata_add($A);
      my $ct = $m->encrypt_last($P);
      my $t = $m->encrypt_done();
      is(unpack('H*', $ct.$t), lc($d->{C}), "encrypt/$count aad_len=" . length($A) . " pt_len=" . length($P));
    }

    { #DECRYPT
      my $m = Crypt::AuthEnc::OCB->new('AES', $K, $N);
      $m->adata_add($A);
      my $pt = $m->decrypt_last(substr($C,0,-16));
      my $t = $m->decrypt_done();
      is(unpack('H*', $pt), lc($d->{P}), "decrypt/$count/a aad_len=" . length($A) . " pt_len=" . length($P));
      is(unpack('H*', $t),  unpack('H*', substr($C,-16)), "decrypt/$count/b aad_len=" . length($A) . " pt_len=" . length($P));
    }

    # $text .= "\t{ /* index:" . ($count-1) . " */\n";
    # $text .= "\t  " . length($P) . ", /* PLAINTEXT length */\n";
    # $text .= "\t  " . length($A) . ", /* AAD length */\n";
    # $text .= "\t  { " . join(',', map { sprintf("0x%02x",unpack('C',$_)) } split(//, $P)) . " }, /* PLAINTEXT */\n";
    # $text .= "\t  { " . join(',', map { sprintf("0x%02x",unpack('C',$_)) } split(//, $A)) . " }, /* AAD */\n";
    # $text .= "\t  { " . join(',', map { sprintf("0x%02x",unpack('C',$_)) } split(//, substr($C,0,-16))) . " }, /* CIPHERTEXT */\n";
    # $text .= "\t  { " . join(',', map { sprintf("0x%02x",unpack('C',$_)) } split(//, substr($C,-16))) . " }, /* TAG */\n";
    # $text .= "\t},\n";

    $d = {};
    $count++;
  }
  else {
    my ($k, $v) = split /:/, $l;
    $d->{$k} = $v;
  }
  
}

#print $text;

__DATA__
#
# test vectors from: http://tools.ietf.org/html/draft-krovetz-ocb-03
#
# This section gives sample output values for various inputs when using
# the AEAD_AES_128_OCB_TAGLEN128 parameters defined in Section 3.1. All
# strings are represented in hexadecimal (eg, 0F represents the
# bitstring 00001111).
#
# Each of the following (A,P,C) triples show the ciphertext C that
# results from OCB-ENCRYPT(K,N,A,P) when K and N are fixed with the
# values
#
#K : 000102030405060708090A0B0C0D0E0F
#N : 000102030405060708090A0B
#
#An empty entry indicates the empty string.

A:
P:
C:197B9C3C441D3C83EAFB2BEF633B9182

A:0001020304050607
P:0001020304050607
C:92B657130A74B85A16DC76A46D47E1EAD537209E8A96D14E

A:0001020304050607
P:
C:98B91552C8C009185044E30A6EB2FE21

A:
P:0001020304050607
C:92B657130A74B85A971EFFCAE19AD4716F88E87B871FBEED

A:000102030405060708090A0B0C0D0E0F
P:000102030405060708090A0B0C0D0E0F
C:BEA5E8798DBE7110031C144DA0B26122776C9924D6723A1FC4524532AC3E5BEB

A:000102030405060708090A0B0C0D0E0F
P:
C:7DDB8E6CEA6814866212509619B19CC6

A:
P:000102030405060708090A0B0C0D0E0F
C:BEA5E8798DBE7110031C144DA0B2612213CC8B747807121A4CBB3E4BD6B456AF

A:000102030405060708090A0B0C0D0E0F1011121314151617
P:000102030405060708090A0B0C0D0E0F1011121314151617
C:BEA5E8798DBE7110031C144DA0B26122FCFCEE7A2A8D4D485FA94FC3F38820F1DC3F3D1FD4E55E1C

A:000102030405060708090A0B0C0D0E0F1011121314151617
P:
C:282026DA3068BC9FA118681D559F10F6

A:
P:000102030405060708090A0B0C0D0E0F1011121314151617
C:BEA5E8798DBE7110031C144DA0B26122FCFCEE7A2A8D4D486EF2F52587FDA0ED97DC7EEDE241DF68

A:000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
P:000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
C:BEA5E8798DBE7110031C144DA0B26122CEAAB9B05DF771A657149D53773463CBB2A040DD3BD5164372D76D7BB6824240

A:000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
P:
C:E1E072633BADE51A60E85951D9C42A1B

A:
P:000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
C:BEA5E8798DBE7110031C144DA0B26122CEAAB9B05DF771A657149D53773463CB4A3BAE824465CFDAF8C41FC50C7DF9D9

A:000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627
P:000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627
C:BEA5E8798DBE7110031C144DA0B26122CEAAB9B05DF771A657149D53773463CB68C65778B058A635659C623211DEEA0DE30D2C381879F4C8

A:000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627
P:
C:7AEB7A69A1687DD082CA27B0D9A37096

A:
P:000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627
C:BEA5E8798DBE7110031C144DA0B26122CEAAB9B05DF771A657149D53773463CB68C65778B058A635060C8467F4ABAB5E8B3C2067A2E115DC

LAST_ITEM_PLACEHOLDER_DO_NOT_DELETE!!!