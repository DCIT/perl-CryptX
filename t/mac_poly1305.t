### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 36 + 8;

use Crypt::Mac::Poly1305 qw( poly1305 poly1305_hex poly1305_b64 poly1305_b64u );

is( unpack('H*', Crypt::Mac::Poly1305->new('12345678901234561234567890123456')->add("")->mac), '31323334353637383930313233343536', 'Poly1305/oo+raw/1');
is( Crypt::Mac::Poly1305->new('12345678901234561234567890123456')->add("")->hexmac, '31323334353637383930313233343536', 'Poly1305/oo+hex/1');
is( unpack('H*', poly1305('12345678901234561234567890123456',"")), '31323334353637383930313233343536', 'Poly1305/func+raw/1');
is( poly1305_hex('12345678901234561234567890123456',""), '31323334353637383930313233343536', 'Poly1305/func+hex/1');
is( poly1305_b64('12345678901234561234567890123456',""), 'MTIzNDU2Nzg5MDEyMzQ1Ng==', 'Poly1305/func+b64/1');
is( poly1305_b64u('12345678901234561234567890123456',""), 'MTIzNDU2Nzg5MDEyMzQ1Ng', 'Poly1305/func+b64u/1');
is( unpack('H*', Crypt::Mac::Poly1305->new('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add("")->mac), '61616161616161616161616161616161', 'Poly1305/oo+raw/2');
is( Crypt::Mac::Poly1305->new('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add("")->hexmac, '61616161616161616161616161616161', 'Poly1305/oo+hex/2');
is( unpack('H*', poly1305('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"")), '61616161616161616161616161616161', 'Poly1305/func+raw/2');
is( poly1305_hex('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',""), '61616161616161616161616161616161', 'Poly1305/func+hex/2');
is( poly1305_b64('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',""), 'YWFhYWFhYWFhYWFhYWFhYQ==', 'Poly1305/func+b64/2');
is( poly1305_b64u('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',""), 'YWFhYWFhYWFhYWFhYWFhYQ', 'Poly1305/func+b64u/2');
is( unpack('H*', Crypt::Mac::Poly1305->new('12345678901234561234567890123456')->add(123)->mac), '57af993261c8bf93c336380cce322860', 'Poly1305/oo+raw/3');
is( Crypt::Mac::Poly1305->new('12345678901234561234567890123456')->add(123)->hexmac, '57af993261c8bf93c336380cce322860', 'Poly1305/oo+hex/3');
is( unpack('H*', poly1305('12345678901234561234567890123456',123)), '57af993261c8bf93c336380cce322860', 'Poly1305/func+raw/3');
is( poly1305_hex('12345678901234561234567890123456',123), '57af993261c8bf93c336380cce322860', 'Poly1305/func+hex/3');
is( poly1305_b64('12345678901234561234567890123456',123), 'V6+ZMmHIv5PDNjgMzjIoYA==', 'Poly1305/func+b64/3');
is( poly1305_b64u('12345678901234561234567890123456',123), 'V6-ZMmHIv5PDNjgMzjIoYA', 'Poly1305/func+b64u/3');
is( unpack('H*', Crypt::Mac::Poly1305->new('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add(123)->mac), '01095f71ce6c2b70ce6c2b70ce6c2b70', 'Poly1305/oo+raw/4');
is( Crypt::Mac::Poly1305->new('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add(123)->hexmac, '01095f71ce6c2b70ce6c2b70ce6c2b70', 'Poly1305/oo+hex/4');
is( unpack('H*', poly1305('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',123)), '01095f71ce6c2b70ce6c2b70ce6c2b70', 'Poly1305/func+raw/4');
is( poly1305_hex('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',123), '01095f71ce6c2b70ce6c2b70ce6c2b70', 'Poly1305/func+hex/4');
is( poly1305_b64('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',123), 'AQlfcc5sK3DObCtwzmwrcA==', 'Poly1305/func+b64/4');
is( poly1305_b64u('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',123), 'AQlfcc5sK3DObCtwzmwrcA', 'Poly1305/func+b64u/4');
is( unpack('H*', Crypt::Mac::Poly1305->new('12345678901234561234567890123456')->add("test\0test\0test\n")->mac), '49181f1f65d313a44a2b224fd5fc0abd', 'Poly1305/oo+raw/5');
is( Crypt::Mac::Poly1305->new('12345678901234561234567890123456')->add("test\0test\0test\n")->hexmac, '49181f1f65d313a44a2b224fd5fc0abd', 'Poly1305/oo+hex/5');
is( unpack('H*', poly1305('12345678901234561234567890123456',"test\0test\0test\n")), '49181f1f65d313a44a2b224fd5fc0abd', 'Poly1305/func+raw/5');
is( poly1305_hex('12345678901234561234567890123456',"test\0test\0test\n"), '49181f1f65d313a44a2b224fd5fc0abd', 'Poly1305/func+hex/5');
is( poly1305_b64('12345678901234561234567890123456',"test\0test\0test\n"), 'SRgfH2XTE6RKKyJP1fwKvQ==', 'Poly1305/func+b64/5');
is( poly1305_b64u('12345678901234561234567890123456',"test\0test\0test\n"), 'SRgfH2XTE6RKKyJP1fwKvQ', 'Poly1305/func+b64u/5');
is( unpack('H*', Crypt::Mac::Poly1305->new('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add("test\0test\0test\n")->mac), '4c02cea60201d83ae4b2d644789422e5', 'Poly1305/oo+raw/6');
is( Crypt::Mac::Poly1305->new('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add("test\0test\0test\n")->hexmac, '4c02cea60201d83ae4b2d644789422e5', 'Poly1305/oo+hex/6');
is( unpack('H*', poly1305('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"test\0test\0test\n")), '4c02cea60201d83ae4b2d644789422e5', 'Poly1305/func+raw/6');
is( poly1305_hex('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"test\0test\0test\n"), '4c02cea60201d83ae4b2d644789422e5', 'Poly1305/func+hex/6');
is( poly1305_b64('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"test\0test\0test\n"), 'TALOpgIB2DrkstZEeJQi5Q==', 'Poly1305/func+b64/6');
is( poly1305_b64u('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"test\0test\0test\n"), 'TALOpgIB2DrkstZEeJQi5Q', 'Poly1305/func+b64u/6');

is( unpack('H*', Crypt::Mac::Poly1305->new('12345678901234561234567890123456')->add("A","A","A")->mac), '7c1e6c34ad72384ac4f52eb49f642abc', 'Poly1305/oo+raw/tripple_A');
is( unpack('H*', Crypt::Mac::Poly1305->new('12345678901234561234567890123456')->add("A")->add("A")->add("A")->mac), '7c1e6c34ad72384ac4f52eb49f642abc', 'Poly1305/oo3+raw/tripple_A');
is( Crypt::Mac::Poly1305->new('12345678901234561234567890123456')->add("A","A","A")->hexmac, '7c1e6c34ad72384ac4f52eb49f642abc', 'Poly1305/oo+hex/tripple_A');
is( Crypt::Mac::Poly1305->new('12345678901234561234567890123456')->add("A")->add("A")->add("A")->hexmac, '7c1e6c34ad72384ac4f52eb49f642abc', 'Poly1305/oo3+hex/tripple_A');
is( unpack('H*', poly1305('12345678901234561234567890123456',"A","A","A")), '7c1e6c34ad72384ac4f52eb49f642abc', 'Poly1305/func+raw/tripple_A');
is( poly1305_hex ('12345678901234561234567890123456',"A","A","A"), '7c1e6c34ad72384ac4f52eb49f642abc',  'Poly1305/func+hex/tripple_A');
is( poly1305_b64 ('12345678901234561234567890123456',"A","A","A"), 'fB5sNK1yOErE9S60n2QqvA==',  'Poly1305/func+b64/tripple_A');
is( poly1305_b64u('12345678901234561234567890123456',"A","A","A"), 'fB5sNK1yOErE9S60n2QqvA', 'Poly1305/func+b64u/tripple_A');
