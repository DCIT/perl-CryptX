### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::SHA224 qw( sha224 sha224_hex sha224_b64 sha224_b64u sha224_file sha224_file_hex sha224_file_b64 sha224_file_b64u );

is( Crypt::Digest::hashsize('SHA224'), 28, 'hashsize/1');
is( Crypt::Digest->hashsize('SHA224'), 28, 'hashsize/2');
is( Crypt::Digest::SHA224::hashsize, 28, 'hashsize/3');
is( Crypt::Digest::SHA224->hashsize, 28, 'hashsize/4');
is( Crypt::Digest->new('SHA224')->hashsize, 28, 'hashsize/5');
is( Crypt::Digest::SHA224->new->hashsize, 28, 'hashsize/6');

is( sha224("A","A","A"), pack("H*","808751af5f7936f20d1c79508d98c079e42ec26802ee238a5a486018"), 'sha224 (raw/tripple_A)');
is( sha224_hex("A","A","A"), "808751af5f7936f20d1c79508d98c079e42ec26802ee238a5a486018", 'sha224 (hex/tripple_A)');
is( sha224_b64("A","A","A"), "gIdRr195NvINHHlQjZjAeeQuwmgC7iOKWkhgGA==", 'sha224 (base64/tripple_A)');
is( sha224_b64u("A","A","A"), "gIdRr195NvINHHlQjZjAeeQuwmgC7iOKWkhgGA", 'sha224 (base64url/tripple_A)');
is( digest_data('SHA224', "A","A","A"), pack("H*","808751af5f7936f20d1c79508d98c079e42ec26802ee238a5a486018"), 'sha224 (digest_data_raw/tripple_A)');
is( digest_data_hex('SHA224', "A","A","A"), "808751af5f7936f20d1c79508d98c079e42ec26802ee238a5a486018", 'sha224 (digest_data_hex/tripple_A)');
is( digest_data_b64('SHA224', "A","A","A"), "gIdRr195NvINHHlQjZjAeeQuwmgC7iOKWkhgGA==", 'sha224 (digest_data_b64/tripple_A)');
is( digest_data_b64u('SHA224', "A","A","A"), "gIdRr195NvINHHlQjZjAeeQuwmgC7iOKWkhgGA", 'sha224 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::SHA224->new->add("A","A","A")->hexdigest, "808751af5f7936f20d1c79508d98c079e42ec26802ee238a5a486018", 'sha224 (OO/tripple_A)');
is( Crypt::Digest::SHA224->new->add("A")->add("A")->add("A")->hexdigest, "808751af5f7936f20d1c79508d98c079e42ec26802ee238a5a486018", 'sha224 (OO3/tripple_A)');


is( sha224(""), pack("H*","d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"), 'sha224 (raw/1)');
is( sha224_hex(""), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", 'sha224 (hex/1)');
is( sha224_b64(""), "0UoCjCo6K8lHYQK7KII0xBWisB+CjqYqxbPkLw==", 'sha224 (base64/1)');
is( digest_data('SHA224', ""), pack("H*","d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"), 'sha224 (digest_data_raw/1)');
is( digest_data_hex('SHA224', ""), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", 'sha224 (digest_data_hex/1)');
is( digest_data_b64('SHA224', ""), "0UoCjCo6K8lHYQK7KII0xBWisB+CjqYqxbPkLw==", 'sha224 (digest_data_b64/1)');
is( digest_data_b64u('SHA224', ""), "0UoCjCo6K8lHYQK7KII0xBWisB-CjqYqxbPkLw", 'sha224 (digest_data_b64u/1)');
is( Crypt::Digest::SHA224->new->add("")->hexdigest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", 'sha224 (OO/1)');

is( sha224("123"), pack("H*","78d8045d684abd2eece923758f3cd781489df3a48e1278982466017f"), 'sha224 (raw/2)');
is( sha224_hex("123"), "78d8045d684abd2eece923758f3cd781489df3a48e1278982466017f", 'sha224 (hex/2)');
is( sha224_b64("123"), "eNgEXWhKvS7s6SN1jzzXgUid86SOEniYJGYBfw==", 'sha224 (base64/2)');
is( digest_data('SHA224', "123"), pack("H*","78d8045d684abd2eece923758f3cd781489df3a48e1278982466017f"), 'sha224 (digest_data_raw/2)');
is( digest_data_hex('SHA224', "123"), "78d8045d684abd2eece923758f3cd781489df3a48e1278982466017f", 'sha224 (digest_data_hex/2)');
is( digest_data_b64('SHA224', "123"), "eNgEXWhKvS7s6SN1jzzXgUid86SOEniYJGYBfw==", 'sha224 (digest_data_b64/2)');
is( digest_data_b64u('SHA224', "123"), "eNgEXWhKvS7s6SN1jzzXgUid86SOEniYJGYBfw", 'sha224 (digest_data_b64u/2)');
is( Crypt::Digest::SHA224->new->add("123")->hexdigest, "78d8045d684abd2eece923758f3cd781489df3a48e1278982466017f", 'sha224 (OO/2)');

is( sha224("test\0test\0test\n"), pack("H*","f4304fb326d85e3b19eefc4ecd772d2fa8d5e20cf9b3c30689bf5d1a"), 'sha224 (raw/3)');
is( sha224_hex("test\0test\0test\n"), "f4304fb326d85e3b19eefc4ecd772d2fa8d5e20cf9b3c30689bf5d1a", 'sha224 (hex/3)');
is( sha224_b64("test\0test\0test\n"), "9DBPsybYXjsZ7vxOzXctL6jV4gz5s8MGib9dGg==", 'sha224 (base64/3)');
is( digest_data('SHA224', "test\0test\0test\n"), pack("H*","f4304fb326d85e3b19eefc4ecd772d2fa8d5e20cf9b3c30689bf5d1a"), 'sha224 (digest_data_raw/3)');
is( digest_data_hex('SHA224', "test\0test\0test\n"), "f4304fb326d85e3b19eefc4ecd772d2fa8d5e20cf9b3c30689bf5d1a", 'sha224 (digest_data_hex/3)');
is( digest_data_b64('SHA224', "test\0test\0test\n"), "9DBPsybYXjsZ7vxOzXctL6jV4gz5s8MGib9dGg==", 'sha224 (digest_data_b64/3)');
is( digest_data_b64u('SHA224', "test\0test\0test\n"), "9DBPsybYXjsZ7vxOzXctL6jV4gz5s8MGib9dGg", 'sha224 (digest_data_b64u/3)');
is( Crypt::Digest::SHA224->new->add("test\0test\0test\n")->hexdigest, "f4304fb326d85e3b19eefc4ecd772d2fa8d5e20cf9b3c30689bf5d1a", 'sha224 (OO/3)');


is( sha224_file('t/data/binary-test.file'), pack("H*","d6fb653a853a333c87bc3e7dbc79ffd62458fb3030f2ef484b252b93"), 'sha224 (raw/file/1)');
is( sha224_file_hex('t/data/binary-test.file'), "d6fb653a853a333c87bc3e7dbc79ffd62458fb3030f2ef484b252b93", 'sha224 (hex/file/1)');
is( sha224_file_b64('t/data/binary-test.file'), "1vtlOoU6MzyHvD59vHn/1iRY+zAw8u9ISyUrkw==", 'sha224 (base64/file/1)');
is( digest_file('SHA224', 't/data/binary-test.file'), pack("H*","d6fb653a853a333c87bc3e7dbc79ffd62458fb3030f2ef484b252b93"), 'sha224 (digest_file_raw/file/1)');
is( digest_file_hex('SHA224', 't/data/binary-test.file'), "d6fb653a853a333c87bc3e7dbc79ffd62458fb3030f2ef484b252b93", 'sha224 (digest_file_hex/file/1)');
is( digest_file_b64('SHA224', 't/data/binary-test.file'), "1vtlOoU6MzyHvD59vHn/1iRY+zAw8u9ISyUrkw==", 'sha224 (digest_file_b64/file/1)');
is( digest_file_b64u('SHA224', 't/data/binary-test.file'), "1vtlOoU6MzyHvD59vHn_1iRY-zAw8u9ISyUrkw", 'sha224 (digest_file_b64u/file/1)');
is( Crypt::Digest::SHA224->new->addfile('t/data/binary-test.file')->hexdigest, "d6fb653a853a333c87bc3e7dbc79ffd62458fb3030f2ef484b252b93", 'sha224 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::SHA224->new->addfile($fh)->hexdigest, "d6fb653a853a333c87bc3e7dbc79ffd62458fb3030f2ef484b252b93", 'sha224 (OO/filehandle/1)');
  close($fh);
}

is( sha224_file('t/data/text-CR.file'), pack("H*","80b23d1856d8e5402088373029c50fca51518aa62a08a4ebc5808399"), 'sha224 (raw/file/2)');
is( sha224_file_hex('t/data/text-CR.file'), "80b23d1856d8e5402088373029c50fca51518aa62a08a4ebc5808399", 'sha224 (hex/file/2)');
is( sha224_file_b64('t/data/text-CR.file'), "gLI9GFbY5UAgiDcwKcUPylFRiqYqCKTrxYCDmQ==", 'sha224 (base64/file/2)');
is( digest_file('SHA224', 't/data/text-CR.file'), pack("H*","80b23d1856d8e5402088373029c50fca51518aa62a08a4ebc5808399"), 'sha224 (digest_file_raw/file/2)');
is( digest_file_hex('SHA224', 't/data/text-CR.file'), "80b23d1856d8e5402088373029c50fca51518aa62a08a4ebc5808399", 'sha224 (digest_file_hex/file/2)');
is( digest_file_b64('SHA224', 't/data/text-CR.file'), "gLI9GFbY5UAgiDcwKcUPylFRiqYqCKTrxYCDmQ==", 'sha224 (digest_file_b64/file/2)');
is( digest_file_b64u('SHA224', 't/data/text-CR.file'), "gLI9GFbY5UAgiDcwKcUPylFRiqYqCKTrxYCDmQ", 'sha224 (digest_file_b64u/file/2)');
is( Crypt::Digest::SHA224->new->addfile('t/data/text-CR.file')->hexdigest, "80b23d1856d8e5402088373029c50fca51518aa62a08a4ebc5808399", 'sha224 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::SHA224->new->addfile($fh)->hexdigest, "80b23d1856d8e5402088373029c50fca51518aa62a08a4ebc5808399", 'sha224 (OO/filehandle/2)');
  close($fh);
}

is( sha224_file('t/data/text-CRLF.file'), pack("H*","106ce90e12970e2a4a14e690c5d519a144ebecab9b5292f31faf3d6e"), 'sha224 (raw/file/3)');
is( sha224_file_hex('t/data/text-CRLF.file'), "106ce90e12970e2a4a14e690c5d519a144ebecab9b5292f31faf3d6e", 'sha224 (hex/file/3)');
is( sha224_file_b64('t/data/text-CRLF.file'), "EGzpDhKXDipKFOaQxdUZoUTr7KubUpLzH689bg==", 'sha224 (base64/file/3)');
is( digest_file('SHA224', 't/data/text-CRLF.file'), pack("H*","106ce90e12970e2a4a14e690c5d519a144ebecab9b5292f31faf3d6e"), 'sha224 (digest_file_raw/file/3)');
is( digest_file_hex('SHA224', 't/data/text-CRLF.file'), "106ce90e12970e2a4a14e690c5d519a144ebecab9b5292f31faf3d6e", 'sha224 (digest_file_hex/file/3)');
is( digest_file_b64('SHA224', 't/data/text-CRLF.file'), "EGzpDhKXDipKFOaQxdUZoUTr7KubUpLzH689bg==", 'sha224 (digest_file_b64/file/3)');
is( digest_file_b64u('SHA224', 't/data/text-CRLF.file'), "EGzpDhKXDipKFOaQxdUZoUTr7KubUpLzH689bg", 'sha224 (digest_file_b64u/file/3)');
is( Crypt::Digest::SHA224->new->addfile('t/data/text-CRLF.file')->hexdigest, "106ce90e12970e2a4a14e690c5d519a144ebecab9b5292f31faf3d6e", 'sha224 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::SHA224->new->addfile($fh)->hexdigest, "106ce90e12970e2a4a14e690c5d519a144ebecab9b5292f31faf3d6e", 'sha224 (OO/filehandle/3)');
  close($fh);
}

is( sha224_file('t/data/text-LF.file'), pack("H*","b854140316344d8f63f90ade619918bddf80a4b46da19f38f55a3d22"), 'sha224 (raw/file/4)');
is( sha224_file_hex('t/data/text-LF.file'), "b854140316344d8f63f90ade619918bddf80a4b46da19f38f55a3d22", 'sha224 (hex/file/4)');
is( sha224_file_b64('t/data/text-LF.file'), "uFQUAxY0TY9j+QreYZkYvd+ApLRtoZ849Vo9Ig==", 'sha224 (base64/file/4)');
is( digest_file('SHA224', 't/data/text-LF.file'), pack("H*","b854140316344d8f63f90ade619918bddf80a4b46da19f38f55a3d22"), 'sha224 (digest_file_raw/file/4)');
is( digest_file_hex('SHA224', 't/data/text-LF.file'), "b854140316344d8f63f90ade619918bddf80a4b46da19f38f55a3d22", 'sha224 (digest_file_hex/file/4)');
is( digest_file_b64('SHA224', 't/data/text-LF.file'), "uFQUAxY0TY9j+QreYZkYvd+ApLRtoZ849Vo9Ig==", 'sha224 (digest_file_b64/file/4)');
is( digest_file_b64u('SHA224', 't/data/text-LF.file'), "uFQUAxY0TY9j-QreYZkYvd-ApLRtoZ849Vo9Ig", 'sha224 (digest_file_b64u/file/4)');
is( Crypt::Digest::SHA224->new->addfile('t/data/text-LF.file')->hexdigest, "b854140316344d8f63f90ade619918bddf80a4b46da19f38f55a3d22", 'sha224 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::SHA224->new->addfile($fh)->hexdigest, "b854140316344d8f63f90ade619918bddf80a4b46da19f38f55a3d22", 'sha224 (OO/filehandle/4)');
  close($fh);
}
