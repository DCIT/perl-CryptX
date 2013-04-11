### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 7*3 + 8*4 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_base64 digest_file digest_file_hex digest_file_base64 );
use Crypt::Digest::Tiger192 qw( tiger192 tiger192_hex tiger192_base64 tiger192_file tiger192_file_hex tiger192_file_base64 );

is( Crypt::Digest::hashsize('Tiger192'), 24, 'hashsize/1');
is( Crypt::Digest->hashsize('Tiger192'), 24, 'hashsize/2');
is( Crypt::Digest::Tiger192::hashsize, 24, 'hashsize/3');
is( Crypt::Digest::Tiger192->hashsize, 24, 'hashsize/4');
is( Crypt::Digest->new('Tiger192')->hashsize, 24, 'hashsize/5');
is( Crypt::Digest::Tiger192->new->hashsize, 24, 'hashsize/6');


is( tiger192(""), pack("H*","3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3"), 'tiger192 (raw/1)');
is( tiger192_hex(""), "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3", 'tiger192 (hex/1)');
is( tiger192_base64(""), "MpOsYwwT8CRfkruxdm4WFnpOWEkt3nPz", 'tiger192 (base64/1)');
is( digest_data('Tiger192', ""), pack("H*","3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3"), 'tiger192 (digest_data_raw/1)');
is( digest_data_hex('Tiger192', ""), "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3", 'tiger192 (digest_data_hex/1)');
is( digest_data_base64('Tiger192', ""), "MpOsYwwT8CRfkruxdm4WFnpOWEkt3nPz", 'tiger192 (digest_data_base64/1)');
is( Crypt::Digest::Tiger192->new->add("")->hexdigest, "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3", 'tiger192 (OO/1)');

is( tiger192(123), pack("H*","a86807bb96a714fe9b22425893e698334cd71e36b0eef2be"), 'tiger192 (raw/2)');
is( tiger192_hex(123), "a86807bb96a714fe9b22425893e698334cd71e36b0eef2be", 'tiger192 (hex/2)');
is( tiger192_base64(123), "qGgHu5anFP6bIkJYk+aYM0zXHjaw7vK+", 'tiger192 (base64/2)');
is( digest_data('Tiger192', 123), pack("H*","a86807bb96a714fe9b22425893e698334cd71e36b0eef2be"), 'tiger192 (digest_data_raw/2)');
is( digest_data_hex('Tiger192', 123), "a86807bb96a714fe9b22425893e698334cd71e36b0eef2be", 'tiger192 (digest_data_hex/2)');
is( digest_data_base64('Tiger192', 123), "qGgHu5anFP6bIkJYk+aYM0zXHjaw7vK+", 'tiger192 (digest_data_base64/2)');
is( Crypt::Digest::Tiger192->new->add(123)->hexdigest, "a86807bb96a714fe9b22425893e698334cd71e36b0eef2be", 'tiger192 (OO/2)');

is( tiger192("test\0test\0test\n"), pack("H*","4d8ed1a51a0f2bcb0f74ae5dee0c7b0a804d98ba9e9a74a1"), 'tiger192 (raw/3)');
is( tiger192_hex("test\0test\0test\n"), "4d8ed1a51a0f2bcb0f74ae5dee0c7b0a804d98ba9e9a74a1", 'tiger192 (hex/3)');
is( tiger192_base64("test\0test\0test\n"), "TY7RpRoPK8sPdK5d7gx7CoBNmLqemnSh", 'tiger192 (base64/3)');
is( digest_data('Tiger192', "test\0test\0test\n"), pack("H*","4d8ed1a51a0f2bcb0f74ae5dee0c7b0a804d98ba9e9a74a1"), 'tiger192 (digest_data_raw/3)');
is( digest_data_hex('Tiger192', "test\0test\0test\n"), "4d8ed1a51a0f2bcb0f74ae5dee0c7b0a804d98ba9e9a74a1", 'tiger192 (digest_data_hex/3)');
is( digest_data_base64('Tiger192', "test\0test\0test\n"), "TY7RpRoPK8sPdK5d7gx7CoBNmLqemnSh", 'tiger192 (digest_data_base64/3)');
is( Crypt::Digest::Tiger192->new->add("test\0test\0test\n")->hexdigest, "4d8ed1a51a0f2bcb0f74ae5dee0c7b0a804d98ba9e9a74a1", 'tiger192 (OO/3)');


is( tiger192_file('t/data/binary-test.file'), pack("H*","87fff912ca5497def55a1a7b5c705ad037a53660432e1d63"), 'tiger192 (raw/file/1)');
is( tiger192_file_hex('t/data/binary-test.file'), "87fff912ca5497def55a1a7b5c705ad037a53660432e1d63", 'tiger192 (hex/file/1)');
is( tiger192_file_base64('t/data/binary-test.file'), "h//5EspUl971Whp7XHBa0DelNmBDLh1j", 'tiger192 (base64/file/1)');
is( digest_file('Tiger192', 't/data/binary-test.file'), pack("H*","87fff912ca5497def55a1a7b5c705ad037a53660432e1d63"), 'tiger192 (digest_file_raw/file/1)');
is( digest_file_hex('Tiger192', 't/data/binary-test.file'), "87fff912ca5497def55a1a7b5c705ad037a53660432e1d63", 'tiger192 (digest_file_hex/file/1)');
is( digest_file_base64('Tiger192', 't/data/binary-test.file'), "h//5EspUl971Whp7XHBa0DelNmBDLh1j", 'tiger192 (digest_file_base64/file/1)');
is( Crypt::Digest::Tiger192->new->addfile('t/data/binary-test.file')->hexdigest, "87fff912ca5497def55a1a7b5c705ad037a53660432e1d63", 'tiger192 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::Tiger192->new->addfile($fh)->hexdigest, "87fff912ca5497def55a1a7b5c705ad037a53660432e1d63", 'tiger192 (OO/filehandle/1)');
  close($fh);
}

is( tiger192_file('t/data/text-CR.file'), pack("H*","3ae7a1ed6473e8049fa12df17256e8f24578d68e9dce447a"), 'tiger192 (raw/file/2)');
is( tiger192_file_hex('t/data/text-CR.file'), "3ae7a1ed6473e8049fa12df17256e8f24578d68e9dce447a", 'tiger192 (hex/file/2)');
is( tiger192_file_base64('t/data/text-CR.file'), "Oueh7WRz6ASfoS3xclbo8kV41o6dzkR6", 'tiger192 (base64/file/2)');
is( digest_file('Tiger192', 't/data/text-CR.file'), pack("H*","3ae7a1ed6473e8049fa12df17256e8f24578d68e9dce447a"), 'tiger192 (digest_file_raw/file/2)');
is( digest_file_hex('Tiger192', 't/data/text-CR.file'), "3ae7a1ed6473e8049fa12df17256e8f24578d68e9dce447a", 'tiger192 (digest_file_hex/file/2)');
is( digest_file_base64('Tiger192', 't/data/text-CR.file'), "Oueh7WRz6ASfoS3xclbo8kV41o6dzkR6", 'tiger192 (digest_file_base64/file/2)');
is( Crypt::Digest::Tiger192->new->addfile('t/data/text-CR.file')->hexdigest, "3ae7a1ed6473e8049fa12df17256e8f24578d68e9dce447a", 'tiger192 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::Tiger192->new->addfile($fh)->hexdigest, "3ae7a1ed6473e8049fa12df17256e8f24578d68e9dce447a", 'tiger192 (OO/filehandle/2)');
  close($fh);
}

is( tiger192_file('t/data/text-CRLF.file'), pack("H*","1d33d392f100dce854ec1e6b71bf58b5724271a9ebfc7b83"), 'tiger192 (raw/file/3)');
is( tiger192_file_hex('t/data/text-CRLF.file'), "1d33d392f100dce854ec1e6b71bf58b5724271a9ebfc7b83", 'tiger192 (hex/file/3)');
is( tiger192_file_base64('t/data/text-CRLF.file'), "HTPTkvEA3OhU7B5rcb9YtXJCcanr/HuD", 'tiger192 (base64/file/3)');
is( digest_file('Tiger192', 't/data/text-CRLF.file'), pack("H*","1d33d392f100dce854ec1e6b71bf58b5724271a9ebfc7b83"), 'tiger192 (digest_file_raw/file/3)');
is( digest_file_hex('Tiger192', 't/data/text-CRLF.file'), "1d33d392f100dce854ec1e6b71bf58b5724271a9ebfc7b83", 'tiger192 (digest_file_hex/file/3)');
is( digest_file_base64('Tiger192', 't/data/text-CRLF.file'), "HTPTkvEA3OhU7B5rcb9YtXJCcanr/HuD", 'tiger192 (digest_file_base64/file/3)');
is( Crypt::Digest::Tiger192->new->addfile('t/data/text-CRLF.file')->hexdigest, "1d33d392f100dce854ec1e6b71bf58b5724271a9ebfc7b83", 'tiger192 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::Tiger192->new->addfile($fh)->hexdigest, "1d33d392f100dce854ec1e6b71bf58b5724271a9ebfc7b83", 'tiger192 (OO/filehandle/3)');
  close($fh);
}

is( tiger192_file('t/data/text-LF.file'), pack("H*","4f4b4a8577833926bec95b6f59d9be248411160593375ba0"), 'tiger192 (raw/file/4)');
is( tiger192_file_hex('t/data/text-LF.file'), "4f4b4a8577833926bec95b6f59d9be248411160593375ba0", 'tiger192 (hex/file/4)');
is( tiger192_file_base64('t/data/text-LF.file'), "T0tKhXeDOSa+yVtvWdm+JIQRFgWTN1ug", 'tiger192 (base64/file/4)');
is( digest_file('Tiger192', 't/data/text-LF.file'), pack("H*","4f4b4a8577833926bec95b6f59d9be248411160593375ba0"), 'tiger192 (digest_file_raw/file/4)');
is( digest_file_hex('Tiger192', 't/data/text-LF.file'), "4f4b4a8577833926bec95b6f59d9be248411160593375ba0", 'tiger192 (digest_file_hex/file/4)');
is( digest_file_base64('Tiger192', 't/data/text-LF.file'), "T0tKhXeDOSa+yVtvWdm+JIQRFgWTN1ug", 'tiger192 (digest_file_base64/file/4)');
is( Crypt::Digest::Tiger192->new->addfile('t/data/text-LF.file')->hexdigest, "4f4b4a8577833926bec95b6f59d9be248411160593375ba0", 'tiger192 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::Tiger192->new->addfile($fh)->hexdigest, "4f4b4a8577833926bec95b6f59d9be248411160593375ba0", 'tiger192 (OO/filehandle/4)');
  close($fh);
}
