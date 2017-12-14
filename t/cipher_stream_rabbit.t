use strict;
use warnings;

use Test::More tests => 3;
use Crypt::Stream::Rabbit;

# https://metacpan.org/source/JCDUQUE/Crypt-Rabbit-1.0.0/t/02.t
# https://metacpan.org/source/JCDUQUE/Crypt-Rabbit-1.0.0/t/03.t
# https://metacpan.org/source/JCDUQUE/Crypt-Rabbit-1.0.0/t/04.t

{
    my $key = pack "H32", 0;
    my $cipher = Crypt::Stream::Rabbit->new($key);
    my $ciphertext = pack "H64", "02f74a1c26456bf5ecd6a536f05457b1a78ac689476c697b390c9cc515d8e888";
    my $plaintext = $cipher->crypt($ciphertext);
    my $answer = unpack "H*", $plaintext;
    is($answer, "0000000000000000000000000000000000000000000000000000000000000000");
}

{
    my $key = pack "H32", "c21fcf3881cd5ee8628accb0a9890df8";
    my $cipher = Crypt::Stream::Rabbit->new($key);
    my $plaintext = pack "H64", 0;
    my $ciphertext = $cipher->crypt($plaintext);
    my $answer = unpack "H*", $ciphertext;
    is($answer, "3d02e0c730559112b473b790dee018dfcd6d730ce54e19f0c35ec4790eb6c74a");
}

{
    my $key = pack "H32", "1d272c6a2d8e3dfcac14056b78d633a0";
    my $cipher = Crypt::Stream::Rabbit->new($key);
    my $plaintext = pack "H72", 0;
    my $ciphertext = $cipher->crypt($plaintext);
    my $answer = unpack "H*", $ciphertext;
    is($answer, "a3a97abb80393820b7e50c4abb53823dc4423799c2efc9ffb3a4125f1f4c99a8ae953e56");
}
