use strict;
use warnings;

use Test::More tests => 6;

use Crypt::Stream::RC4;
use Crypt::Stream::Sober128;
use Crypt::Stream::ChaCha;

{
  my $key = pack("H*", "0123456789abcdef");
  my $pt  = pack("H*", "0123456789abcdef");
  my $ct  = pack("H*", "75b7878099e0c596");
  my $enc = Crypt::Stream::RC4->new($key)->crypt($pt);
  my $dec = Crypt::Stream::RC4->new($key)->crypt($ct);
  is(unpack("H*", $enc), unpack("H*", $ct), "Crypt::Stream::RC4 encrypt");
  is(unpack("H*", $dec), unpack("H*", $pt), "Crypt::Stream::RC4 decrypt");
}

{
  my $key = pack("H*", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  my $iv  = pack("H*", "000000000000004a00000000");
  my $ct  = pack("H*", "6E2E359A2568F98041BA0728DD0D6981E97E7AEC1D4360C20A27AFCCFD9FAE0BF91B65C5524733AB".
                      "8F593DABCD62B3571639D624E65152AB8F530C359F0861D807CA0DBF500D6A6156A38E088A22B65E".
                      "52BC514D16CCF806818CE91AB77937365AF90BBF74A35BE6B40B8EEDF2785E42874D");
  my $pt  = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
  my $enc = Crypt::Stream::ChaCha->new($key, $iv, 1, 20)->crypt($pt);
  my $dec = Crypt::Stream::ChaCha->new($key, $iv, 1, 20)->crypt($ct);
  is(unpack("H*", $enc), unpack("H*", $ct), "Crypt::Stream::ChaCha encrypt");
  is($dec, $pt, "Crypt::Stream::ChaCha decrypt");
}

{
  my $key = pack("H*", "74657374206b65792031323862697473");
  my $iv  = pack("H*", "00000000");
  my $ct  = pack("H*", "43500ccf89919f1daa377495f4b458c240378bbb");
  my $pt  = pack("H*", "0000000000000000000000000000000000000000");
  my $enc = Crypt::Stream::Sober128->new($key, $iv)->crypt($pt);
  my $dec = Crypt::Stream::Sober128->new($key, $iv)->crypt($ct);
  is(unpack("H*", $enc), unpack("H*", $ct), "Crypt::Stream::Sober128 encrypt");
  is(unpack("H*", $dec), unpack("H*", $pt), "Crypt::Stream::Sober128 decrypt");
}
