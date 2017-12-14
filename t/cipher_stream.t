use strict;
use warnings;

use Test::More tests => 20;

use Crypt::Stream::RC4;
use Crypt::Stream::Sober128;
use Crypt::Stream::ChaCha;
use Crypt::Stream::Salsa20;
use Crypt::Stream::Sosemanuk;
use Crypt::Stream::Rabbit;

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

{
  my $key = pack("H*", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  my $iv  = pack("H*", "000000000000004a");
  my $ct  = pack("H*", "CB68DCC5725E0EB8ADB47F526DCF821AD3E95D87EB4FAB3E92BE23CFF6C462CC1193527AC840DC43".
                       "772891D89A4AD56871EA7E5119B167C6FDAD7507F4A86DCE33326D570C62876EAE76210C4F3F8B77".
                       "C3EB7301C812FE432DE52C5A0665EA976F9C9D67EBB01A1657F4C67758BBAA2D2D12");
  my $pt  = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
  my $enc = Crypt::Stream::Salsa20->new($key, $iv, 1, 20)->crypt($pt);
  my $dec = Crypt::Stream::Salsa20->new($key, $iv, 1, 20)->crypt($ct);
  is(unpack("H*", $enc), unpack("H*", $ct), "Crypt::Stream::Salsa encrypt");
  is($dec, $pt, "Crypt::Stream::Salsa decrypt");
}

{
  my $key = pack("H*", "74657374206b65792031323862697473");
  my $iv  = pack("H*", "11223344");
  my $ct  = pack("H*", "c57260e45b747f4223c2fb3b372c3c0f8091686e");
  my $pt  = pack("H*", "f31f8df318512fe05a6ee39aec075c2318071d27");
  my $enc = Crypt::Stream::Sosemanuk->new($key, $iv)->crypt($pt);
  my $dec = Crypt::Stream::Sosemanuk->new($key, $iv)->crypt($ct);
  is(unpack("H*", $enc), unpack("H*", $ct), "Crypt::Stream::Sosemanuk encrypt");
  is(unpack("H*", $dec), unpack("H*", $pt), "Crypt::Stream::Sosemanuk decrypt");
}
{
  my $key = pack("H*", "74657374206b65792031323862697473");
  my $ct  = pack("H*", "366ded17432550a279ac18a1db2b602c98967549");
  my $pt  = pack("H*", "f31f8df318512fe05a6ee39aec075c2318071d27");
  my $enc = Crypt::Stream::Sosemanuk->new($key, "")->crypt($pt);
  my $dec = Crypt::Stream::Sosemanuk->new($key, "")->crypt($ct);
  is(unpack("H*", $enc), unpack("H*", $ct), "Crypt::Stream::Sosemanuk encrypt (empty IV)");
  is(unpack("H*", $dec), unpack("H*", $pt), "Crypt::Stream::Sosemanuk decrypt (empty IV)");
}
{
  my $key = pack("H*", "74657374206b65792031323862697473");
  my $ct  = pack("H*", "366ded17432550a279ac18a1db2b602c98967549");
  my $pt  = pack("H*", "f31f8df318512fe05a6ee39aec075c2318071d27");
  my $enc = Crypt::Stream::Sosemanuk->new($key)->crypt($pt);
  my $dec = Crypt::Stream::Sosemanuk->new($key)->crypt($ct);
  is(unpack("H*", $enc), unpack("H*", $ct), "Crypt::Stream::Sosemanuk encrypt (no IV)");
  is(unpack("H*", $dec), unpack("H*", $pt), "Crypt::Stream::Sosemanuk decrypt (no IV)");
}

{
  my $key = pack("H*", "74657374206b65792031323862697473");
  my $iv  = pack("H*", "1122334455");
  my $ct  = pack("H*", "91d4ba9044faa26e08db767d34b88d5cf4c884db");
  my $pt  = pack("H*", "0000000000000000000000000000000000000000");
  my $enc = Crypt::Stream::Rabbit->new($key, $iv)->crypt($pt);
  my $dec = Crypt::Stream::Rabbit->new($key, $iv)->crypt($ct);
  is(unpack("H*", $enc), unpack("H*", $ct), "Crypt::Stream::Rabbit encrypt");
  is(unpack("H*", $dec), unpack("H*", $pt), "Crypt::Stream::Rabbit decrypt");
}
{
  my $key = pack("H*", "74657374206b65792031323862697473");
  my $ct  = pack("H*", "e8c99affb8ffb7541b6da2e06887994e800b70c9");
  my $pt  = pack("H*", "0000000000000000000000000000000000000000");
  my $enc = Crypt::Stream::Rabbit->new($key)->crypt($pt);
  my $dec = Crypt::Stream::Rabbit->new($key)->crypt($ct);
  is(unpack("H*", $enc), unpack("H*", $ct), "Crypt::Stream::Rabbit encrypt (no IV)");
  is(unpack("H*", $dec), unpack("H*", $pt), "Crypt::Stream::Rabbit decrypt (no IV)");
}
{
  my $key = pack("H*", "74657374206b65792031323862697473");
  my $ct  = pack("H*", "442cf424c5da8d78000c6b874050260792ae8ce0");
  my $pt  = pack("H*", "0000000000000000000000000000000000000000");
  my $enc = Crypt::Stream::Rabbit->new($key, "")->crypt($pt);
  my $dec = Crypt::Stream::Rabbit->new($key, "")->crypt($ct);
  is(unpack("H*", $enc), unpack("H*", $ct), "Crypt::Stream::Rabbit encrypt (empty IV)");
  is(unpack("H*", $dec), unpack("H*", $pt), "Crypt::Stream::Rabbit decrypt (empty IV)");
}
