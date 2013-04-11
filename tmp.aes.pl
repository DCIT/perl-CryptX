use Crypt::Cipher::AES;
use Crypt::OpenSSL::AES;

my $a1 = Crypt::Cipher::AES->new('12345678901234567890123456789012');
warn $a1->blocksize;

my $a2 = Crypt::OpenSSL::AES->new('12345678901234567890123456789012');
warn $a2->blocksize;

warn Crypt::Cipher::AES->blocksize;
warn Crypt::OpenSSL::AES->blocksize;


use Crypt::CBC;

my $cipher = Crypt::CBC->new( -key => 'my secret key', -cipher => 'Cipher::AES' );
my $ciphertext = $cipher->encrypt("This data is hush hush");
my $plaintext  = $cipher->decrypt($ciphertext);
die "ERROR" unless $plaintext eq "This data is hush hush";
