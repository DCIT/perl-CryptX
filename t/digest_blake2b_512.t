### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::BLAKE2b_512 qw( blake2b_512 blake2b_512_hex blake2b_512_b64 blake2b_512_b64u blake2b_512_file blake2b_512_file_hex blake2b_512_file_b64 blake2b_512_file_b64u );

is( Crypt::Digest::hashsize('BLAKE2b_512'), 64, 'hashsize/1');
is( Crypt::Digest->hashsize('BLAKE2b_512'), 64, 'hashsize/2');
is( Crypt::Digest::BLAKE2b_512::hashsize, 64, 'hashsize/3');
is( Crypt::Digest::BLAKE2b_512->hashsize, 64, 'hashsize/4');
is( Crypt::Digest->new('BLAKE2b_512')->hashsize, 64, 'hashsize/5');
is( Crypt::Digest::BLAKE2b_512->new->hashsize, 64, 'hashsize/6');

is( blake2b_512("A","A","A"), pack("H*","dda5c92ae5adba047d317f99dc58a9059b5a8c0907f95d8cddcf5bfdaa8e4c74ddd84bc2683cdc2d16a340ff5798e1bf4bd2c838332611f266bb62870d33b823"), 'blake2b_512 (raw/tripple_A)');
is( blake2b_512_hex("A","A","A"), "dda5c92ae5adba047d317f99dc58a9059b5a8c0907f95d8cddcf5bfdaa8e4c74ddd84bc2683cdc2d16a340ff5798e1bf4bd2c838332611f266bb62870d33b823", 'blake2b_512 (hex/tripple_A)');
is( blake2b_512_b64("A","A","A"), "3aXJKuWtugR9MX+Z3FipBZtajAkH+V2M3c9b/aqOTHTd2EvCaDzcLRajQP9XmOG/S9LIODMmEfJmu2KHDTO4Iw==", 'blake2b_512 (base64/tripple_A)');
is( blake2b_512_b64u("A","A","A"), "3aXJKuWtugR9MX-Z3FipBZtajAkH-V2M3c9b_aqOTHTd2EvCaDzcLRajQP9XmOG_S9LIODMmEfJmu2KHDTO4Iw", 'blake2b_512 (base64url/tripple_A)');
is( digest_data('BLAKE2b_512', "A","A","A"), pack("H*","dda5c92ae5adba047d317f99dc58a9059b5a8c0907f95d8cddcf5bfdaa8e4c74ddd84bc2683cdc2d16a340ff5798e1bf4bd2c838332611f266bb62870d33b823"), 'blake2b_512 (digest_data_raw/tripple_A)');
is( digest_data_hex('BLAKE2b_512', "A","A","A"), "dda5c92ae5adba047d317f99dc58a9059b5a8c0907f95d8cddcf5bfdaa8e4c74ddd84bc2683cdc2d16a340ff5798e1bf4bd2c838332611f266bb62870d33b823", 'blake2b_512 (digest_data_hex/tripple_A)');
is( digest_data_b64('BLAKE2b_512', "A","A","A"), "3aXJKuWtugR9MX+Z3FipBZtajAkH+V2M3c9b/aqOTHTd2EvCaDzcLRajQP9XmOG/S9LIODMmEfJmu2KHDTO4Iw==", 'blake2b_512 (digest_data_b64/tripple_A)');
is( digest_data_b64u('BLAKE2b_512', "A","A","A"), "3aXJKuWtugR9MX-Z3FipBZtajAkH-V2M3c9b_aqOTHTd2EvCaDzcLRajQP9XmOG_S9LIODMmEfJmu2KHDTO4Iw", 'blake2b_512 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::BLAKE2b_512->new->add("A","A","A")->hexdigest, "dda5c92ae5adba047d317f99dc58a9059b5a8c0907f95d8cddcf5bfdaa8e4c74ddd84bc2683cdc2d16a340ff5798e1bf4bd2c838332611f266bb62870d33b823", 'blake2b_512 (OO/tripple_A)');
is( Crypt::Digest::BLAKE2b_512->new->add("A")->add("A")->add("A")->hexdigest, "dda5c92ae5adba047d317f99dc58a9059b5a8c0907f95d8cddcf5bfdaa8e4c74ddd84bc2683cdc2d16a340ff5798e1bf4bd2c838332611f266bb62870d33b823", 'blake2b_512 (OO3/tripple_A)');


is( blake2b_512(""), pack("H*","786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"), 'blake2b_512 (raw/1)');
is( blake2b_512_hex(""), "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce", 'blake2b_512 (hex/1)');
is( blake2b_512_b64(""), "eGoC90IBWQPGxv2FJVLScpEvR0DhWEdhiobiF/cfVBnSXhAxr+5YUxOJZESTTrBLkDpoWxRIt1XVb3Aa/pvizg==", 'blake2b_512 (base64/1)');
is( digest_data('BLAKE2b_512', ""), pack("H*","786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"), 'blake2b_512 (digest_data_raw/1)');
is( digest_data_hex('BLAKE2b_512', ""), "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce", 'blake2b_512 (digest_data_hex/1)');
is( digest_data_b64('BLAKE2b_512', ""), "eGoC90IBWQPGxv2FJVLScpEvR0DhWEdhiobiF/cfVBnSXhAxr+5YUxOJZESTTrBLkDpoWxRIt1XVb3Aa/pvizg==", 'blake2b_512 (digest_data_b64/1)');
is( digest_data_b64u('BLAKE2b_512', ""), "eGoC90IBWQPGxv2FJVLScpEvR0DhWEdhiobiF_cfVBnSXhAxr-5YUxOJZESTTrBLkDpoWxRIt1XVb3Aa_pvizg", 'blake2b_512 (digest_data_b64u/1)');
is( Crypt::Digest::BLAKE2b_512->new->add("")->hexdigest, "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce", 'blake2b_512 (OO/1)');

is( blake2b_512("123"), pack("H*","e64cb91c7c1819bdcda4dca47a2aae98e737df75ddb0287083229dc0695064616df676a0c95ae55109fe0a27ba9dee79ea9a5c9d90cceb0cf8ae80b4f61ab4a3"), 'blake2b_512 (raw/2)');
is( blake2b_512_hex("123"), "e64cb91c7c1819bdcda4dca47a2aae98e737df75ddb0287083229dc0695064616df676a0c95ae55109fe0a27ba9dee79ea9a5c9d90cceb0cf8ae80b4f61ab4a3", 'blake2b_512 (hex/2)');
is( blake2b_512_b64("123"), "5ky5HHwYGb3NpNykeiqumOc333XdsChwgyKdwGlQZGFt9nagyVrlUQn+Cie6ne556ppcnZDM6wz4roC09hq0ow==", 'blake2b_512 (base64/2)');
is( digest_data('BLAKE2b_512', "123"), pack("H*","e64cb91c7c1819bdcda4dca47a2aae98e737df75ddb0287083229dc0695064616df676a0c95ae55109fe0a27ba9dee79ea9a5c9d90cceb0cf8ae80b4f61ab4a3"), 'blake2b_512 (digest_data_raw/2)');
is( digest_data_hex('BLAKE2b_512', "123"), "e64cb91c7c1819bdcda4dca47a2aae98e737df75ddb0287083229dc0695064616df676a0c95ae55109fe0a27ba9dee79ea9a5c9d90cceb0cf8ae80b4f61ab4a3", 'blake2b_512 (digest_data_hex/2)');
is( digest_data_b64('BLAKE2b_512', "123"), "5ky5HHwYGb3NpNykeiqumOc333XdsChwgyKdwGlQZGFt9nagyVrlUQn+Cie6ne556ppcnZDM6wz4roC09hq0ow==", 'blake2b_512 (digest_data_b64/2)');
is( digest_data_b64u('BLAKE2b_512', "123"), "5ky5HHwYGb3NpNykeiqumOc333XdsChwgyKdwGlQZGFt9nagyVrlUQn-Cie6ne556ppcnZDM6wz4roC09hq0ow", 'blake2b_512 (digest_data_b64u/2)');
is( Crypt::Digest::BLAKE2b_512->new->add("123")->hexdigest, "e64cb91c7c1819bdcda4dca47a2aae98e737df75ddb0287083229dc0695064616df676a0c95ae55109fe0a27ba9dee79ea9a5c9d90cceb0cf8ae80b4f61ab4a3", 'blake2b_512 (OO/2)');

is( blake2b_512("test\0test\0test\n"), pack("H*","fd8d99f76c34c8c6ad60d7842ed769a9d32dc619efc8618761db5a8f1851089b8adfaf40f73ac5f0acf75307bbeda9769764c386e715cc758ce0ee6dfe184400"), 'blake2b_512 (raw/3)');
is( blake2b_512_hex("test\0test\0test\n"), "fd8d99f76c34c8c6ad60d7842ed769a9d32dc619efc8618761db5a8f1851089b8adfaf40f73ac5f0acf75307bbeda9769764c386e715cc758ce0ee6dfe184400", 'blake2b_512 (hex/3)');
is( blake2b_512_b64("test\0test\0test\n"), "/Y2Z92w0yMatYNeELtdpqdMtxhnvyGGHYdtajxhRCJuK369A9zrF8Kz3Uwe77al2l2TDhucVzHWM4O5t/hhEAA==", 'blake2b_512 (base64/3)');
is( digest_data('BLAKE2b_512', "test\0test\0test\n"), pack("H*","fd8d99f76c34c8c6ad60d7842ed769a9d32dc619efc8618761db5a8f1851089b8adfaf40f73ac5f0acf75307bbeda9769764c386e715cc758ce0ee6dfe184400"), 'blake2b_512 (digest_data_raw/3)');
is( digest_data_hex('BLAKE2b_512', "test\0test\0test\n"), "fd8d99f76c34c8c6ad60d7842ed769a9d32dc619efc8618761db5a8f1851089b8adfaf40f73ac5f0acf75307bbeda9769764c386e715cc758ce0ee6dfe184400", 'blake2b_512 (digest_data_hex/3)');
is( digest_data_b64('BLAKE2b_512', "test\0test\0test\n"), "/Y2Z92w0yMatYNeELtdpqdMtxhnvyGGHYdtajxhRCJuK369A9zrF8Kz3Uwe77al2l2TDhucVzHWM4O5t/hhEAA==", 'blake2b_512 (digest_data_b64/3)');
is( digest_data_b64u('BLAKE2b_512', "test\0test\0test\n"), "_Y2Z92w0yMatYNeELtdpqdMtxhnvyGGHYdtajxhRCJuK369A9zrF8Kz3Uwe77al2l2TDhucVzHWM4O5t_hhEAA", 'blake2b_512 (digest_data_b64u/3)');
is( Crypt::Digest::BLAKE2b_512->new->add("test\0test\0test\n")->hexdigest, "fd8d99f76c34c8c6ad60d7842ed769a9d32dc619efc8618761db5a8f1851089b8adfaf40f73ac5f0acf75307bbeda9769764c386e715cc758ce0ee6dfe184400", 'blake2b_512 (OO/3)');


is( blake2b_512_file('t/data/binary-test.file'), pack("H*","4be101a45bde3785c069f79673e1189a8d9dcaa2482a0fde0c2cc75807aa83f3e0d3747692f09b6708ac00a3c642900b0f8bc64f1e7bce40c043eaeae8583c0b"), 'blake2b_512 (raw/file/1)');
is( blake2b_512_file_hex('t/data/binary-test.file'), "4be101a45bde3785c069f79673e1189a8d9dcaa2482a0fde0c2cc75807aa83f3e0d3747692f09b6708ac00a3c642900b0f8bc64f1e7bce40c043eaeae8583c0b", 'blake2b_512 (hex/file/1)');
is( blake2b_512_file_b64('t/data/binary-test.file'), "S+EBpFveN4XAafeWc+EYmo2dyqJIKg/eDCzHWAeqg/Pg03R2kvCbZwisAKPGQpALD4vGTx57zkDAQ+rq6Fg8Cw==", 'blake2b_512 (base64/file/1)');
is( digest_file('BLAKE2b_512', 't/data/binary-test.file'), pack("H*","4be101a45bde3785c069f79673e1189a8d9dcaa2482a0fde0c2cc75807aa83f3e0d3747692f09b6708ac00a3c642900b0f8bc64f1e7bce40c043eaeae8583c0b"), 'blake2b_512 (digest_file_raw/file/1)');
is( digest_file_hex('BLAKE2b_512', 't/data/binary-test.file'), "4be101a45bde3785c069f79673e1189a8d9dcaa2482a0fde0c2cc75807aa83f3e0d3747692f09b6708ac00a3c642900b0f8bc64f1e7bce40c043eaeae8583c0b", 'blake2b_512 (digest_file_hex/file/1)');
is( digest_file_b64('BLAKE2b_512', 't/data/binary-test.file'), "S+EBpFveN4XAafeWc+EYmo2dyqJIKg/eDCzHWAeqg/Pg03R2kvCbZwisAKPGQpALD4vGTx57zkDAQ+rq6Fg8Cw==", 'blake2b_512 (digest_file_b64/file/1)');
is( digest_file_b64u('BLAKE2b_512', 't/data/binary-test.file'), "S-EBpFveN4XAafeWc-EYmo2dyqJIKg_eDCzHWAeqg_Pg03R2kvCbZwisAKPGQpALD4vGTx57zkDAQ-rq6Fg8Cw", 'blake2b_512 (digest_file_b64u/file/1)');
is( Crypt::Digest::BLAKE2b_512->new->addfile('t/data/binary-test.file')->hexdigest, "4be101a45bde3785c069f79673e1189a8d9dcaa2482a0fde0c2cc75807aa83f3e0d3747692f09b6708ac00a3c642900b0f8bc64f1e7bce40c043eaeae8583c0b", 'blake2b_512 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_512->new->addfile($fh)->hexdigest, "4be101a45bde3785c069f79673e1189a8d9dcaa2482a0fde0c2cc75807aa83f3e0d3747692f09b6708ac00a3c642900b0f8bc64f1e7bce40c043eaeae8583c0b", 'blake2b_512 (OO/filehandle/1)');
  close($fh);
}

is( blake2b_512_file('t/data/text-CR.file'), pack("H*","49a5a632d6e83d3978ee5a583d81af8e9504fae4861f680e5a7258bb2ead5d44c8a0b6b194f21ac68328c1c62b8ed23025e5d64674d052bf9b171e88418ca16c"), 'blake2b_512 (raw/file/2)');
is( blake2b_512_file_hex('t/data/text-CR.file'), "49a5a632d6e83d3978ee5a583d81af8e9504fae4861f680e5a7258bb2ead5d44c8a0b6b194f21ac68328c1c62b8ed23025e5d64674d052bf9b171e88418ca16c", 'blake2b_512 (hex/file/2)');
is( blake2b_512_file_b64('t/data/text-CR.file'), "SaWmMtboPTl47lpYPYGvjpUE+uSGH2gOWnJYuy6tXUTIoLaxlPIaxoMowcYrjtIwJeXWRnTQUr+bFx6IQYyhbA==", 'blake2b_512 (base64/file/2)');
is( digest_file('BLAKE2b_512', 't/data/text-CR.file'), pack("H*","49a5a632d6e83d3978ee5a583d81af8e9504fae4861f680e5a7258bb2ead5d44c8a0b6b194f21ac68328c1c62b8ed23025e5d64674d052bf9b171e88418ca16c"), 'blake2b_512 (digest_file_raw/file/2)');
is( digest_file_hex('BLAKE2b_512', 't/data/text-CR.file'), "49a5a632d6e83d3978ee5a583d81af8e9504fae4861f680e5a7258bb2ead5d44c8a0b6b194f21ac68328c1c62b8ed23025e5d64674d052bf9b171e88418ca16c", 'blake2b_512 (digest_file_hex/file/2)');
is( digest_file_b64('BLAKE2b_512', 't/data/text-CR.file'), "SaWmMtboPTl47lpYPYGvjpUE+uSGH2gOWnJYuy6tXUTIoLaxlPIaxoMowcYrjtIwJeXWRnTQUr+bFx6IQYyhbA==", 'blake2b_512 (digest_file_b64/file/2)');
is( digest_file_b64u('BLAKE2b_512', 't/data/text-CR.file'), "SaWmMtboPTl47lpYPYGvjpUE-uSGH2gOWnJYuy6tXUTIoLaxlPIaxoMowcYrjtIwJeXWRnTQUr-bFx6IQYyhbA", 'blake2b_512 (digest_file_b64u/file/2)');
is( Crypt::Digest::BLAKE2b_512->new->addfile('t/data/text-CR.file')->hexdigest, "49a5a632d6e83d3978ee5a583d81af8e9504fae4861f680e5a7258bb2ead5d44c8a0b6b194f21ac68328c1c62b8ed23025e5d64674d052bf9b171e88418ca16c", 'blake2b_512 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_512->new->addfile($fh)->hexdigest, "49a5a632d6e83d3978ee5a583d81af8e9504fae4861f680e5a7258bb2ead5d44c8a0b6b194f21ac68328c1c62b8ed23025e5d64674d052bf9b171e88418ca16c", 'blake2b_512 (OO/filehandle/2)');
  close($fh);
}

is( blake2b_512_file('t/data/text-CRLF.file'), pack("H*","5df2606edf6508ae927e6d0fb769abed4c5dc82f99c2e8f9da1c52c0d0bc3c325446b3cb4d47ffc689d01a9676783946dd4a132bce3c31a8fafd2eeb27107a7e"), 'blake2b_512 (raw/file/3)');
is( blake2b_512_file_hex('t/data/text-CRLF.file'), "5df2606edf6508ae927e6d0fb769abed4c5dc82f99c2e8f9da1c52c0d0bc3c325446b3cb4d47ffc689d01a9676783946dd4a132bce3c31a8fafd2eeb27107a7e", 'blake2b_512 (hex/file/3)');
is( blake2b_512_file_b64('t/data/text-CRLF.file'), "XfJgbt9lCK6Sfm0Pt2mr7UxdyC+Zwuj52hxSwNC8PDJURrPLTUf/xonQGpZ2eDlG3UoTK848Maj6/S7rJxB6fg==", 'blake2b_512 (base64/file/3)');
is( digest_file('BLAKE2b_512', 't/data/text-CRLF.file'), pack("H*","5df2606edf6508ae927e6d0fb769abed4c5dc82f99c2e8f9da1c52c0d0bc3c325446b3cb4d47ffc689d01a9676783946dd4a132bce3c31a8fafd2eeb27107a7e"), 'blake2b_512 (digest_file_raw/file/3)');
is( digest_file_hex('BLAKE2b_512', 't/data/text-CRLF.file'), "5df2606edf6508ae927e6d0fb769abed4c5dc82f99c2e8f9da1c52c0d0bc3c325446b3cb4d47ffc689d01a9676783946dd4a132bce3c31a8fafd2eeb27107a7e", 'blake2b_512 (digest_file_hex/file/3)');
is( digest_file_b64('BLAKE2b_512', 't/data/text-CRLF.file'), "XfJgbt9lCK6Sfm0Pt2mr7UxdyC+Zwuj52hxSwNC8PDJURrPLTUf/xonQGpZ2eDlG3UoTK848Maj6/S7rJxB6fg==", 'blake2b_512 (digest_file_b64/file/3)');
is( digest_file_b64u('BLAKE2b_512', 't/data/text-CRLF.file'), "XfJgbt9lCK6Sfm0Pt2mr7UxdyC-Zwuj52hxSwNC8PDJURrPLTUf_xonQGpZ2eDlG3UoTK848Maj6_S7rJxB6fg", 'blake2b_512 (digest_file_b64u/file/3)');
is( Crypt::Digest::BLAKE2b_512->new->addfile('t/data/text-CRLF.file')->hexdigest, "5df2606edf6508ae927e6d0fb769abed4c5dc82f99c2e8f9da1c52c0d0bc3c325446b3cb4d47ffc689d01a9676783946dd4a132bce3c31a8fafd2eeb27107a7e", 'blake2b_512 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_512->new->addfile($fh)->hexdigest, "5df2606edf6508ae927e6d0fb769abed4c5dc82f99c2e8f9da1c52c0d0bc3c325446b3cb4d47ffc689d01a9676783946dd4a132bce3c31a8fafd2eeb27107a7e", 'blake2b_512 (OO/filehandle/3)');
  close($fh);
}

is( blake2b_512_file('t/data/text-LF.file'), pack("H*","adaa42f339d50111fd407ad5c3f2c27b81d8560eb1283f69a3449a59a801617c98001a54396c095734a229905f2aa4dffaaf5ceca077a3a55960c66089e9309e"), 'blake2b_512 (raw/file/4)');
is( blake2b_512_file_hex('t/data/text-LF.file'), "adaa42f339d50111fd407ad5c3f2c27b81d8560eb1283f69a3449a59a801617c98001a54396c095734a229905f2aa4dffaaf5ceca077a3a55960c66089e9309e", 'blake2b_512 (hex/file/4)');
is( blake2b_512_file_b64('t/data/text-LF.file'), "rapC8znVARH9QHrVw/LCe4HYVg6xKD9po0SaWagBYXyYABpUOWwJVzSiKZBfKqTf+q9c7KB3o6VZYMZgiekwng==", 'blake2b_512 (base64/file/4)');
is( digest_file('BLAKE2b_512', 't/data/text-LF.file'), pack("H*","adaa42f339d50111fd407ad5c3f2c27b81d8560eb1283f69a3449a59a801617c98001a54396c095734a229905f2aa4dffaaf5ceca077a3a55960c66089e9309e"), 'blake2b_512 (digest_file_raw/file/4)');
is( digest_file_hex('BLAKE2b_512', 't/data/text-LF.file'), "adaa42f339d50111fd407ad5c3f2c27b81d8560eb1283f69a3449a59a801617c98001a54396c095734a229905f2aa4dffaaf5ceca077a3a55960c66089e9309e", 'blake2b_512 (digest_file_hex/file/4)');
is( digest_file_b64('BLAKE2b_512', 't/data/text-LF.file'), "rapC8znVARH9QHrVw/LCe4HYVg6xKD9po0SaWagBYXyYABpUOWwJVzSiKZBfKqTf+q9c7KB3o6VZYMZgiekwng==", 'blake2b_512 (digest_file_b64/file/4)');
is( digest_file_b64u('BLAKE2b_512', 't/data/text-LF.file'), "rapC8znVARH9QHrVw_LCe4HYVg6xKD9po0SaWagBYXyYABpUOWwJVzSiKZBfKqTf-q9c7KB3o6VZYMZgiekwng", 'blake2b_512 (digest_file_b64u/file/4)');
is( Crypt::Digest::BLAKE2b_512->new->addfile('t/data/text-LF.file')->hexdigest, "adaa42f339d50111fd407ad5c3f2c27b81d8560eb1283f69a3449a59a801617c98001a54396c095734a229905f2aa4dffaaf5ceca077a3a55960c66089e9309e", 'blake2b_512 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_512->new->addfile($fh)->hexdigest, "adaa42f339d50111fd407ad5c3f2c27b81d8560eb1283f69a3449a59a801617c98001a54396c095734a229905f2aa4dffaaf5ceca077a3a55960c66089e9309e", 'blake2b_512 (OO/filehandle/4)');
  close($fh);
}
