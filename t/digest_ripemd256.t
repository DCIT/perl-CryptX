### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::RIPEMD256 qw( ripemd256 ripemd256_hex ripemd256_b64 ripemd256_b64u ripemd256_file ripemd256_file_hex ripemd256_file_b64 ripemd256_file_b64u );

is( Crypt::Digest::hashsize('RIPEMD256'), 32, 'hashsize/1');
is( Crypt::Digest->hashsize('RIPEMD256'), 32, 'hashsize/2');
is( Crypt::Digest::RIPEMD256::hashsize, 32, 'hashsize/3');
is( Crypt::Digest::RIPEMD256->hashsize, 32, 'hashsize/4');
is( Crypt::Digest->new('RIPEMD256')->hashsize, 32, 'hashsize/5');
is( Crypt::Digest::RIPEMD256->new->hashsize, 32, 'hashsize/6');

is( ripemd256("A","A","A"), pack("H*","0c976582631435d4fbc424758105a05a622ae27726f395774858d7ea2b2f5d82"), 'ripemd256 (raw/tripple_A)');
is( ripemd256_hex("A","A","A"), "0c976582631435d4fbc424758105a05a622ae27726f395774858d7ea2b2f5d82", 'ripemd256 (hex/tripple_A)');
is( ripemd256_b64("A","A","A"), "DJdlgmMUNdT7xCR1gQWgWmIq4ncm85V3SFjX6isvXYI=", 'ripemd256 (base64/tripple_A)');
is( ripemd256_b64u("A","A","A"), "DJdlgmMUNdT7xCR1gQWgWmIq4ncm85V3SFjX6isvXYI", 'ripemd256 (base64url/tripple_A)');
is( digest_data('RIPEMD256', "A","A","A"), pack("H*","0c976582631435d4fbc424758105a05a622ae27726f395774858d7ea2b2f5d82"), 'ripemd256 (digest_data_raw/tripple_A)');
is( digest_data_hex('RIPEMD256', "A","A","A"), "0c976582631435d4fbc424758105a05a622ae27726f395774858d7ea2b2f5d82", 'ripemd256 (digest_data_hex/tripple_A)');
is( digest_data_b64('RIPEMD256', "A","A","A"), "DJdlgmMUNdT7xCR1gQWgWmIq4ncm85V3SFjX6isvXYI=", 'ripemd256 (digest_data_b64/tripple_A)');
is( digest_data_b64u('RIPEMD256', "A","A","A"), "DJdlgmMUNdT7xCR1gQWgWmIq4ncm85V3SFjX6isvXYI", 'ripemd256 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::RIPEMD256->new->add("A","A","A")->hexdigest, "0c976582631435d4fbc424758105a05a622ae27726f395774858d7ea2b2f5d82", 'ripemd256 (OO/tripple_A)');
is( Crypt::Digest::RIPEMD256->new->add("A")->add("A")->add("A")->hexdigest, "0c976582631435d4fbc424758105a05a622ae27726f395774858d7ea2b2f5d82", 'ripemd256 (OO3/tripple_A)');


is( ripemd256(""), pack("H*","02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d"), 'ripemd256 (raw/1)');
is( ripemd256_hex(""), "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d", 'ripemd256 (hex/1)');
is( ripemd256_b64(""), "ArpMTl+OzRh3/FLWTTDjei2XdPseXQJjgK4BaOPFUi0=", 'ripemd256 (base64/1)');
is( digest_data('RIPEMD256', ""), pack("H*","02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d"), 'ripemd256 (digest_data_raw/1)');
is( digest_data_hex('RIPEMD256', ""), "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d", 'ripemd256 (digest_data_hex/1)');
is( digest_data_b64('RIPEMD256', ""), "ArpMTl+OzRh3/FLWTTDjei2XdPseXQJjgK4BaOPFUi0=", 'ripemd256 (digest_data_b64/1)');
is( digest_data_b64u('RIPEMD256', ""), "ArpMTl-OzRh3_FLWTTDjei2XdPseXQJjgK4BaOPFUi0", 'ripemd256 (digest_data_b64u/1)');
is( Crypt::Digest::RIPEMD256->new->add("")->hexdigest, "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d", 'ripemd256 (OO/1)');

is( ripemd256("123"), pack("H*","8536753ad7bface2dba89fb318c95b1b42890016057d4c3a2f351cec3acbb28b"), 'ripemd256 (raw/2)');
is( ripemd256_hex("123"), "8536753ad7bface2dba89fb318c95b1b42890016057d4c3a2f351cec3acbb28b", 'ripemd256 (hex/2)');
is( ripemd256_b64("123"), "hTZ1Ote/rOLbqJ+zGMlbG0KJABYFfUw6LzUc7DrLsos=", 'ripemd256 (base64/2)');
is( digest_data('RIPEMD256', "123"), pack("H*","8536753ad7bface2dba89fb318c95b1b42890016057d4c3a2f351cec3acbb28b"), 'ripemd256 (digest_data_raw/2)');
is( digest_data_hex('RIPEMD256', "123"), "8536753ad7bface2dba89fb318c95b1b42890016057d4c3a2f351cec3acbb28b", 'ripemd256 (digest_data_hex/2)');
is( digest_data_b64('RIPEMD256', "123"), "hTZ1Ote/rOLbqJ+zGMlbG0KJABYFfUw6LzUc7DrLsos=", 'ripemd256 (digest_data_b64/2)');
is( digest_data_b64u('RIPEMD256', "123"), "hTZ1Ote_rOLbqJ-zGMlbG0KJABYFfUw6LzUc7DrLsos", 'ripemd256 (digest_data_b64u/2)');
is( Crypt::Digest::RIPEMD256->new->add("123")->hexdigest, "8536753ad7bface2dba89fb318c95b1b42890016057d4c3a2f351cec3acbb28b", 'ripemd256 (OO/2)');

is( ripemd256("test\0test\0test\n"), pack("H*","31c2bd4e721bb8fa911022bbc51ddc74943772a951f300bd4e4c9dfceddb10e5"), 'ripemd256 (raw/3)');
is( ripemd256_hex("test\0test\0test\n"), "31c2bd4e721bb8fa911022bbc51ddc74943772a951f300bd4e4c9dfceddb10e5", 'ripemd256 (hex/3)');
is( ripemd256_b64("test\0test\0test\n"), "McK9TnIbuPqRECK7xR3cdJQ3cqlR8wC9Tkyd/O3bEOU=", 'ripemd256 (base64/3)');
is( digest_data('RIPEMD256', "test\0test\0test\n"), pack("H*","31c2bd4e721bb8fa911022bbc51ddc74943772a951f300bd4e4c9dfceddb10e5"), 'ripemd256 (digest_data_raw/3)');
is( digest_data_hex('RIPEMD256', "test\0test\0test\n"), "31c2bd4e721bb8fa911022bbc51ddc74943772a951f300bd4e4c9dfceddb10e5", 'ripemd256 (digest_data_hex/3)');
is( digest_data_b64('RIPEMD256', "test\0test\0test\n"), "McK9TnIbuPqRECK7xR3cdJQ3cqlR8wC9Tkyd/O3bEOU=", 'ripemd256 (digest_data_b64/3)');
is( digest_data_b64u('RIPEMD256', "test\0test\0test\n"), "McK9TnIbuPqRECK7xR3cdJQ3cqlR8wC9Tkyd_O3bEOU", 'ripemd256 (digest_data_b64u/3)');
is( Crypt::Digest::RIPEMD256->new->add("test\0test\0test\n")->hexdigest, "31c2bd4e721bb8fa911022bbc51ddc74943772a951f300bd4e4c9dfceddb10e5", 'ripemd256 (OO/3)');


is( ripemd256_file('t/data/binary-test.file'), pack("H*","04045c33e656c780c9fe908d819322fd031b5fc8e009c2d03bd2ba9fcc1ff8c8"), 'ripemd256 (raw/file/1)');
is( ripemd256_file_hex('t/data/binary-test.file'), "04045c33e656c780c9fe908d819322fd031b5fc8e009c2d03bd2ba9fcc1ff8c8", 'ripemd256 (hex/file/1)');
is( ripemd256_file_b64('t/data/binary-test.file'), "BARcM+ZWx4DJ/pCNgZMi/QMbX8jgCcLQO9K6n8wf+Mg=", 'ripemd256 (base64/file/1)');
is( digest_file('RIPEMD256', 't/data/binary-test.file'), pack("H*","04045c33e656c780c9fe908d819322fd031b5fc8e009c2d03bd2ba9fcc1ff8c8"), 'ripemd256 (digest_file_raw/file/1)');
is( digest_file_hex('RIPEMD256', 't/data/binary-test.file'), "04045c33e656c780c9fe908d819322fd031b5fc8e009c2d03bd2ba9fcc1ff8c8", 'ripemd256 (digest_file_hex/file/1)');
is( digest_file_b64('RIPEMD256', 't/data/binary-test.file'), "BARcM+ZWx4DJ/pCNgZMi/QMbX8jgCcLQO9K6n8wf+Mg=", 'ripemd256 (digest_file_b64/file/1)');
is( digest_file_b64u('RIPEMD256', 't/data/binary-test.file'), "BARcM-ZWx4DJ_pCNgZMi_QMbX8jgCcLQO9K6n8wf-Mg", 'ripemd256 (digest_file_b64u/file/1)');
is( Crypt::Digest::RIPEMD256->new->addfile('t/data/binary-test.file')->hexdigest, "04045c33e656c780c9fe908d819322fd031b5fc8e009c2d03bd2ba9fcc1ff8c8", 'ripemd256 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD256->new->addfile($fh)->hexdigest, "04045c33e656c780c9fe908d819322fd031b5fc8e009c2d03bd2ba9fcc1ff8c8", 'ripemd256 (OO/filehandle/1)');
  close($fh);
}

is( ripemd256_file('t/data/text-CR.file'), pack("H*","9f4e9323acd154c0731e7e9f1b0c4af2c37831b1457c591cd4c19b3f79c930d4"), 'ripemd256 (raw/file/2)');
is( ripemd256_file_hex('t/data/text-CR.file'), "9f4e9323acd154c0731e7e9f1b0c4af2c37831b1457c591cd4c19b3f79c930d4", 'ripemd256 (hex/file/2)');
is( ripemd256_file_b64('t/data/text-CR.file'), "n06TI6zRVMBzHn6fGwxK8sN4MbFFfFkc1MGbP3nJMNQ=", 'ripemd256 (base64/file/2)');
is( digest_file('RIPEMD256', 't/data/text-CR.file'), pack("H*","9f4e9323acd154c0731e7e9f1b0c4af2c37831b1457c591cd4c19b3f79c930d4"), 'ripemd256 (digest_file_raw/file/2)');
is( digest_file_hex('RIPEMD256', 't/data/text-CR.file'), "9f4e9323acd154c0731e7e9f1b0c4af2c37831b1457c591cd4c19b3f79c930d4", 'ripemd256 (digest_file_hex/file/2)');
is( digest_file_b64('RIPEMD256', 't/data/text-CR.file'), "n06TI6zRVMBzHn6fGwxK8sN4MbFFfFkc1MGbP3nJMNQ=", 'ripemd256 (digest_file_b64/file/2)');
is( digest_file_b64u('RIPEMD256', 't/data/text-CR.file'), "n06TI6zRVMBzHn6fGwxK8sN4MbFFfFkc1MGbP3nJMNQ", 'ripemd256 (digest_file_b64u/file/2)');
is( Crypt::Digest::RIPEMD256->new->addfile('t/data/text-CR.file')->hexdigest, "9f4e9323acd154c0731e7e9f1b0c4af2c37831b1457c591cd4c19b3f79c930d4", 'ripemd256 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD256->new->addfile($fh)->hexdigest, "9f4e9323acd154c0731e7e9f1b0c4af2c37831b1457c591cd4c19b3f79c930d4", 'ripemd256 (OO/filehandle/2)');
  close($fh);
}

is( ripemd256_file('t/data/text-CRLF.file'), pack("H*","687ec071c90af42e551a3df07196e9d27ec5c4e1744fe17a0e2eb27dc9109611"), 'ripemd256 (raw/file/3)');
is( ripemd256_file_hex('t/data/text-CRLF.file'), "687ec071c90af42e551a3df07196e9d27ec5c4e1744fe17a0e2eb27dc9109611", 'ripemd256 (hex/file/3)');
is( ripemd256_file_b64('t/data/text-CRLF.file'), "aH7AcckK9C5VGj3wcZbp0n7FxOF0T+F6Di6yfckQlhE=", 'ripemd256 (base64/file/3)');
is( digest_file('RIPEMD256', 't/data/text-CRLF.file'), pack("H*","687ec071c90af42e551a3df07196e9d27ec5c4e1744fe17a0e2eb27dc9109611"), 'ripemd256 (digest_file_raw/file/3)');
is( digest_file_hex('RIPEMD256', 't/data/text-CRLF.file'), "687ec071c90af42e551a3df07196e9d27ec5c4e1744fe17a0e2eb27dc9109611", 'ripemd256 (digest_file_hex/file/3)');
is( digest_file_b64('RIPEMD256', 't/data/text-CRLF.file'), "aH7AcckK9C5VGj3wcZbp0n7FxOF0T+F6Di6yfckQlhE=", 'ripemd256 (digest_file_b64/file/3)');
is( digest_file_b64u('RIPEMD256', 't/data/text-CRLF.file'), "aH7AcckK9C5VGj3wcZbp0n7FxOF0T-F6Di6yfckQlhE", 'ripemd256 (digest_file_b64u/file/3)');
is( Crypt::Digest::RIPEMD256->new->addfile('t/data/text-CRLF.file')->hexdigest, "687ec071c90af42e551a3df07196e9d27ec5c4e1744fe17a0e2eb27dc9109611", 'ripemd256 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD256->new->addfile($fh)->hexdigest, "687ec071c90af42e551a3df07196e9d27ec5c4e1744fe17a0e2eb27dc9109611", 'ripemd256 (OO/filehandle/3)');
  close($fh);
}

is( ripemd256_file('t/data/text-LF.file'), pack("H*","ef8b4d7c754269584403b4672e5abe44972b36a4ddb66a2a489e11041cbe7413"), 'ripemd256 (raw/file/4)');
is( ripemd256_file_hex('t/data/text-LF.file'), "ef8b4d7c754269584403b4672e5abe44972b36a4ddb66a2a489e11041cbe7413", 'ripemd256 (hex/file/4)');
is( ripemd256_file_b64('t/data/text-LF.file'), "74tNfHVCaVhEA7RnLlq+RJcrNqTdtmoqSJ4RBBy+dBM=", 'ripemd256 (base64/file/4)');
is( digest_file('RIPEMD256', 't/data/text-LF.file'), pack("H*","ef8b4d7c754269584403b4672e5abe44972b36a4ddb66a2a489e11041cbe7413"), 'ripemd256 (digest_file_raw/file/4)');
is( digest_file_hex('RIPEMD256', 't/data/text-LF.file'), "ef8b4d7c754269584403b4672e5abe44972b36a4ddb66a2a489e11041cbe7413", 'ripemd256 (digest_file_hex/file/4)');
is( digest_file_b64('RIPEMD256', 't/data/text-LF.file'), "74tNfHVCaVhEA7RnLlq+RJcrNqTdtmoqSJ4RBBy+dBM=", 'ripemd256 (digest_file_b64/file/4)');
is( digest_file_b64u('RIPEMD256', 't/data/text-LF.file'), "74tNfHVCaVhEA7RnLlq-RJcrNqTdtmoqSJ4RBBy-dBM", 'ripemd256 (digest_file_b64u/file/4)');
is( Crypt::Digest::RIPEMD256->new->addfile('t/data/text-LF.file')->hexdigest, "ef8b4d7c754269584403b4672e5abe44972b36a4ddb66a2a489e11041cbe7413", 'ripemd256 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD256->new->addfile($fh)->hexdigest, "ef8b4d7c754269584403b4672e5abe44972b36a4ddb66a2a489e11041cbe7413", 'ripemd256 (OO/filehandle/4)');
  close($fh);
}
