use strict;
use warnings;

# tests from Crypt::IDEA

use Test::More tests => 55;
use Crypt::Cipher::IDEA;

my @TEST_SUITE = (
 [qw( 00010002000300040005000600070008  0000000100020003  11FBED2B01986DE5 )],
 [qw( 00010002000300040005000600070008  0102030405060708  540E5FEA18C2F8B1 )],
 [qw( 00010002000300040005000600070008  0019324B647D96AF  9F0A0AB6E10CED78 )],
 [qw( 00010002000300040005000600070008  F5202D5B9C671B08  CF18FD7355E2C5C5 )],
 [qw( 00010002000300040005000600070008  FAE6D2BEAA96826E  85DF52005608193D )],
 [qw( 00010002000300040005000600070008  0A141E28323C4650  2F7DE750212FB734 )],
 [qw( 00010002000300040005000600070008  050A0F14191E2328  7B7314925DE59C09 )],
 [qw( 0005000A000F00140019001E00230028  0102030405060708  3EC04780BEFF6E20 )],
 [qw( 3A984E2000195DB32EE501C8C47CEA60  0102030405060708  97BCD8200780DA86 )],
 [qw( 006400C8012C019001F4025802BC0320  05320A6414C819FA  65BE87E7A2538AED )],
 [qw( 9D4075C103BC322AFB03E7BE6AB30006  0808080808080808  F5DB1AC45E5EF9F9 )],
);

# Run a cipher test case
sub test {
    my ($case, $key, $in, $out) = @_;

    # Pack structures
    my ($p_key, $p_in, $p_out) = map { pack("H*", $_) } ($key, $in, $out);

    # Create a new cipher
    my $cipher = Crypt::Cipher::IDEA->new($p_key);
    isa_ok( $cipher, "Crypt::Cipher", "(c$case) Test object construction" );

    # Key tests
    is( $cipher->blocksize(),  8, "(c$case) Test cipher block size" );
    is( $cipher->keysize(),   16, "(c$case) Test cipher key size"   );

    # Encrypt
    my $e_test = uc unpack("H*", $cipher->encrypt($p_in));
    is( $e_test,  $out, "(c$case) Test Encryption" );

    # Decrypt
    my $d_test = uc unpack("H*", $cipher->decrypt($p_out));
    is( $d_test,   $in, "(c$case) Test Decryption" );
}

# Run all test cases
for (my $i = 0; $i <= $#TEST_SUITE; $i++) {
  test($i, @{ $TEST_SUITE[$i] });
}
