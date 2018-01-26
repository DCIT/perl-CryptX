### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::MD2 qw( md2 md2_hex md2_b64 md2_b64u md2_file md2_file_hex md2_file_b64 md2_file_b64u );

is( Crypt::Digest::hashsize('MD2'), 16, 'hashsize/1');
is( Crypt::Digest->hashsize('MD2'), 16, 'hashsize/2');
is( Crypt::Digest::MD2::hashsize, 16, 'hashsize/3');
is( Crypt::Digest::MD2->hashsize, 16, 'hashsize/4');
is( Crypt::Digest->new('MD2')->hashsize, 16, 'hashsize/5');
is( Crypt::Digest::MD2->new->hashsize, 16, 'hashsize/6');

is( md2("A","A","A"), pack("H*","8788c1729761fdad983b830f04b19e86"), 'md2 (raw/tripple_A)');
is( md2_hex("A","A","A"), "8788c1729761fdad983b830f04b19e86", 'md2 (hex/tripple_A)');
is( md2_b64("A","A","A"), "h4jBcpdh/a2YO4MPBLGehg==", 'md2 (base64/tripple_A)');
is( md2_b64u("A","A","A"), "h4jBcpdh_a2YO4MPBLGehg", 'md2 (base64url/tripple_A)');
is( digest_data('MD2', "A","A","A"), pack("H*","8788c1729761fdad983b830f04b19e86"), 'md2 (digest_data_raw/tripple_A)');
is( digest_data_hex('MD2', "A","A","A"), "8788c1729761fdad983b830f04b19e86", 'md2 (digest_data_hex/tripple_A)');
is( digest_data_b64('MD2', "A","A","A"), "h4jBcpdh/a2YO4MPBLGehg==", 'md2 (digest_data_b64/tripple_A)');
is( digest_data_b64u('MD2', "A","A","A"), "h4jBcpdh_a2YO4MPBLGehg", 'md2 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::MD2->new->add("A","A","A")->hexdigest, "8788c1729761fdad983b830f04b19e86", 'md2 (OO/tripple_A)');
is( Crypt::Digest::MD2->new->add("A")->add("A")->add("A")->hexdigest, "8788c1729761fdad983b830f04b19e86", 'md2 (OO3/tripple_A)');


is( md2(""), pack("H*","8350e5a3e24c153df2275c9f80692773"), 'md2 (raw/1)');
is( md2_hex(""), "8350e5a3e24c153df2275c9f80692773", 'md2 (hex/1)');
is( md2_b64(""), "g1Dlo+JMFT3yJ1yfgGkncw==", 'md2 (base64/1)');
is( digest_data('MD2', ""), pack("H*","8350e5a3e24c153df2275c9f80692773"), 'md2 (digest_data_raw/1)');
is( digest_data_hex('MD2', ""), "8350e5a3e24c153df2275c9f80692773", 'md2 (digest_data_hex/1)');
is( digest_data_b64('MD2', ""), "g1Dlo+JMFT3yJ1yfgGkncw==", 'md2 (digest_data_b64/1)');
is( digest_data_b64u('MD2', ""), "g1Dlo-JMFT3yJ1yfgGkncw", 'md2 (digest_data_b64u/1)');
is( Crypt::Digest::MD2->new->add("")->hexdigest, "8350e5a3e24c153df2275c9f80692773", 'md2 (OO/1)');

is( md2("123"), pack("H*","ef1fedf5d32ead6b7aaf687de4ed1b71"), 'md2 (raw/2)');
is( md2_hex("123"), "ef1fedf5d32ead6b7aaf687de4ed1b71", 'md2 (hex/2)');
is( md2_b64("123"), "7x/t9dMurWt6r2h95O0bcQ==", 'md2 (base64/2)');
is( digest_data('MD2', "123"), pack("H*","ef1fedf5d32ead6b7aaf687de4ed1b71"), 'md2 (digest_data_raw/2)');
is( digest_data_hex('MD2', "123"), "ef1fedf5d32ead6b7aaf687de4ed1b71", 'md2 (digest_data_hex/2)');
is( digest_data_b64('MD2', "123"), "7x/t9dMurWt6r2h95O0bcQ==", 'md2 (digest_data_b64/2)');
is( digest_data_b64u('MD2', "123"), "7x_t9dMurWt6r2h95O0bcQ", 'md2 (digest_data_b64u/2)');
is( Crypt::Digest::MD2->new->add("123")->hexdigest, "ef1fedf5d32ead6b7aaf687de4ed1b71", 'md2 (OO/2)');

is( md2("test\0test\0test\n"), pack("H*","2ab87f6a63c5a8095e4b1207f3ff860c"), 'md2 (raw/3)');
is( md2_hex("test\0test\0test\n"), "2ab87f6a63c5a8095e4b1207f3ff860c", 'md2 (hex/3)');
is( md2_b64("test\0test\0test\n"), "Krh/amPFqAleSxIH8/+GDA==", 'md2 (base64/3)');
is( digest_data('MD2', "test\0test\0test\n"), pack("H*","2ab87f6a63c5a8095e4b1207f3ff860c"), 'md2 (digest_data_raw/3)');
is( digest_data_hex('MD2', "test\0test\0test\n"), "2ab87f6a63c5a8095e4b1207f3ff860c", 'md2 (digest_data_hex/3)');
is( digest_data_b64('MD2', "test\0test\0test\n"), "Krh/amPFqAleSxIH8/+GDA==", 'md2 (digest_data_b64/3)');
is( digest_data_b64u('MD2', "test\0test\0test\n"), "Krh_amPFqAleSxIH8_-GDA", 'md2 (digest_data_b64u/3)');
is( Crypt::Digest::MD2->new->add("test\0test\0test\n")->hexdigest, "2ab87f6a63c5a8095e4b1207f3ff860c", 'md2 (OO/3)');


is( md2_file('t/data/binary-test.file'), pack("H*","43fa4a403cf2b9826a72154d56bc09a7"), 'md2 (raw/file/1)');
is( md2_file_hex('t/data/binary-test.file'), "43fa4a403cf2b9826a72154d56bc09a7", 'md2 (hex/file/1)');
is( md2_file_b64('t/data/binary-test.file'), "Q/pKQDzyuYJqchVNVrwJpw==", 'md2 (base64/file/1)');
is( digest_file('MD2', 't/data/binary-test.file'), pack("H*","43fa4a403cf2b9826a72154d56bc09a7"), 'md2 (digest_file_raw/file/1)');
is( digest_file_hex('MD2', 't/data/binary-test.file'), "43fa4a403cf2b9826a72154d56bc09a7", 'md2 (digest_file_hex/file/1)');
is( digest_file_b64('MD2', 't/data/binary-test.file'), "Q/pKQDzyuYJqchVNVrwJpw==", 'md2 (digest_file_b64/file/1)');
is( digest_file_b64u('MD2', 't/data/binary-test.file'), "Q_pKQDzyuYJqchVNVrwJpw", 'md2 (digest_file_b64u/file/1)');
is( Crypt::Digest::MD2->new->addfile('t/data/binary-test.file')->hexdigest, "43fa4a403cf2b9826a72154d56bc09a7", 'md2 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::MD2->new->addfile($fh)->hexdigest, "43fa4a403cf2b9826a72154d56bc09a7", 'md2 (OO/filehandle/1)');
  close($fh);
}

is( md2_file('t/data/text-CR.file'), pack("H*","aefb6839dad1aa061e231e9c3aeb7ad0"), 'md2 (raw/file/2)');
is( md2_file_hex('t/data/text-CR.file'), "aefb6839dad1aa061e231e9c3aeb7ad0", 'md2 (hex/file/2)');
is( md2_file_b64('t/data/text-CR.file'), "rvtoOdrRqgYeIx6cOut60A==", 'md2 (base64/file/2)');
is( digest_file('MD2', 't/data/text-CR.file'), pack("H*","aefb6839dad1aa061e231e9c3aeb7ad0"), 'md2 (digest_file_raw/file/2)');
is( digest_file_hex('MD2', 't/data/text-CR.file'), "aefb6839dad1aa061e231e9c3aeb7ad0", 'md2 (digest_file_hex/file/2)');
is( digest_file_b64('MD2', 't/data/text-CR.file'), "rvtoOdrRqgYeIx6cOut60A==", 'md2 (digest_file_b64/file/2)');
is( digest_file_b64u('MD2', 't/data/text-CR.file'), "rvtoOdrRqgYeIx6cOut60A", 'md2 (digest_file_b64u/file/2)');
is( Crypt::Digest::MD2->new->addfile('t/data/text-CR.file')->hexdigest, "aefb6839dad1aa061e231e9c3aeb7ad0", 'md2 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::MD2->new->addfile($fh)->hexdigest, "aefb6839dad1aa061e231e9c3aeb7ad0", 'md2 (OO/filehandle/2)');
  close($fh);
}

is( md2_file('t/data/text-CRLF.file'), pack("H*","5c32665f8372b97aa1d8ed733d88f50e"), 'md2 (raw/file/3)');
is( md2_file_hex('t/data/text-CRLF.file'), "5c32665f8372b97aa1d8ed733d88f50e", 'md2 (hex/file/3)');
is( md2_file_b64('t/data/text-CRLF.file'), "XDJmX4NyuXqh2O1zPYj1Dg==", 'md2 (base64/file/3)');
is( digest_file('MD2', 't/data/text-CRLF.file'), pack("H*","5c32665f8372b97aa1d8ed733d88f50e"), 'md2 (digest_file_raw/file/3)');
is( digest_file_hex('MD2', 't/data/text-CRLF.file'), "5c32665f8372b97aa1d8ed733d88f50e", 'md2 (digest_file_hex/file/3)');
is( digest_file_b64('MD2', 't/data/text-CRLF.file'), "XDJmX4NyuXqh2O1zPYj1Dg==", 'md2 (digest_file_b64/file/3)');
is( digest_file_b64u('MD2', 't/data/text-CRLF.file'), "XDJmX4NyuXqh2O1zPYj1Dg", 'md2 (digest_file_b64u/file/3)');
is( Crypt::Digest::MD2->new->addfile('t/data/text-CRLF.file')->hexdigest, "5c32665f8372b97aa1d8ed733d88f50e", 'md2 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::MD2->new->addfile($fh)->hexdigest, "5c32665f8372b97aa1d8ed733d88f50e", 'md2 (OO/filehandle/3)');
  close($fh);
}

is( md2_file('t/data/text-LF.file'), pack("H*","0e4142ba5bdaa257e4c618f9b309784c"), 'md2 (raw/file/4)');
is( md2_file_hex('t/data/text-LF.file'), "0e4142ba5bdaa257e4c618f9b309784c", 'md2 (hex/file/4)');
is( md2_file_b64('t/data/text-LF.file'), "DkFCulvaolfkxhj5swl4TA==", 'md2 (base64/file/4)');
is( digest_file('MD2', 't/data/text-LF.file'), pack("H*","0e4142ba5bdaa257e4c618f9b309784c"), 'md2 (digest_file_raw/file/4)');
is( digest_file_hex('MD2', 't/data/text-LF.file'), "0e4142ba5bdaa257e4c618f9b309784c", 'md2 (digest_file_hex/file/4)');
is( digest_file_b64('MD2', 't/data/text-LF.file'), "DkFCulvaolfkxhj5swl4TA==", 'md2 (digest_file_b64/file/4)');
is( digest_file_b64u('MD2', 't/data/text-LF.file'), "DkFCulvaolfkxhj5swl4TA", 'md2 (digest_file_b64u/file/4)');
is( Crypt::Digest::MD2->new->addfile('t/data/text-LF.file')->hexdigest, "0e4142ba5bdaa257e4c618f9b309784c", 'md2 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::MD2->new->addfile($fh)->hexdigest, "0e4142ba5bdaa257e4c618f9b309784c", 'md2 (OO/filehandle/4)');
  close($fh);
}
