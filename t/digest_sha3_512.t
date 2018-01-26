### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::SHA3_512 qw( sha3_512 sha3_512_hex sha3_512_b64 sha3_512_b64u sha3_512_file sha3_512_file_hex sha3_512_file_b64 sha3_512_file_b64u );

is( Crypt::Digest::hashsize('SHA3_512'), 64, 'hashsize/1');
is( Crypt::Digest->hashsize('SHA3_512'), 64, 'hashsize/2');
is( Crypt::Digest::SHA3_512::hashsize, 64, 'hashsize/3');
is( Crypt::Digest::SHA3_512->hashsize, 64, 'hashsize/4');
is( Crypt::Digest->new('SHA3_512')->hashsize, 64, 'hashsize/5');
is( Crypt::Digest::SHA3_512->new->hashsize, 64, 'hashsize/6');

is( sha3_512("A","A","A"), pack("H*","852cf44eb8d38715c847976b6de526564136d756fa99b4ad5a825fd6e3ba5d891c7b4576b11410a6e951fffa3399b14be1da4222d53b5a35ff236d659899e857"), 'sha3_512 (raw/tripple_A)');
is( sha3_512_hex("A","A","A"), "852cf44eb8d38715c847976b6de526564136d756fa99b4ad5a825fd6e3ba5d891c7b4576b11410a6e951fffa3399b14be1da4222d53b5a35ff236d659899e857", 'sha3_512 (hex/tripple_A)');
is( sha3_512_b64("A","A","A"), "hSz0TrjThxXIR5drbeUmVkE211b6mbStWoJf1uO6XYkce0V2sRQQpulR//ozmbFL4dpCItU7WjX/I21lmJnoVw==", 'sha3_512 (base64/tripple_A)');
is( sha3_512_b64u("A","A","A"), "hSz0TrjThxXIR5drbeUmVkE211b6mbStWoJf1uO6XYkce0V2sRQQpulR__ozmbFL4dpCItU7WjX_I21lmJnoVw", 'sha3_512 (base64url/tripple_A)');
is( digest_data('SHA3_512', "A","A","A"), pack("H*","852cf44eb8d38715c847976b6de526564136d756fa99b4ad5a825fd6e3ba5d891c7b4576b11410a6e951fffa3399b14be1da4222d53b5a35ff236d659899e857"), 'sha3_512 (digest_data_raw/tripple_A)');
is( digest_data_hex('SHA3_512', "A","A","A"), "852cf44eb8d38715c847976b6de526564136d756fa99b4ad5a825fd6e3ba5d891c7b4576b11410a6e951fffa3399b14be1da4222d53b5a35ff236d659899e857", 'sha3_512 (digest_data_hex/tripple_A)');
is( digest_data_b64('SHA3_512', "A","A","A"), "hSz0TrjThxXIR5drbeUmVkE211b6mbStWoJf1uO6XYkce0V2sRQQpulR//ozmbFL4dpCItU7WjX/I21lmJnoVw==", 'sha3_512 (digest_data_b64/tripple_A)');
is( digest_data_b64u('SHA3_512', "A","A","A"), "hSz0TrjThxXIR5drbeUmVkE211b6mbStWoJf1uO6XYkce0V2sRQQpulR__ozmbFL4dpCItU7WjX_I21lmJnoVw", 'sha3_512 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::SHA3_512->new->add("A","A","A")->hexdigest, "852cf44eb8d38715c847976b6de526564136d756fa99b4ad5a825fd6e3ba5d891c7b4576b11410a6e951fffa3399b14be1da4222d53b5a35ff236d659899e857", 'sha3_512 (OO/tripple_A)');
is( Crypt::Digest::SHA3_512->new->add("A")->add("A")->add("A")->hexdigest, "852cf44eb8d38715c847976b6de526564136d756fa99b4ad5a825fd6e3ba5d891c7b4576b11410a6e951fffa3399b14be1da4222d53b5a35ff236d659899e857", 'sha3_512 (OO3/tripple_A)');


is( sha3_512(""), pack("H*","a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"), 'sha3_512 (raw/1)');
is( sha3_512_hex(""), "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26", 'sha3_512 (hex/1)');
is( sha3_512_b64(""), "pp9zzKI6msXItWfcGFp1bpfJghZP4lhZ4NHcwUdcgKYVshI68fX5TBHj6UAsOsVY9QAZnZW20+MBdYWGKB3NJg==", 'sha3_512 (base64/1)');
is( digest_data('SHA3_512', ""), pack("H*","a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"), 'sha3_512 (digest_data_raw/1)');
is( digest_data_hex('SHA3_512', ""), "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26", 'sha3_512 (digest_data_hex/1)');
is( digest_data_b64('SHA3_512', ""), "pp9zzKI6msXItWfcGFp1bpfJghZP4lhZ4NHcwUdcgKYVshI68fX5TBHj6UAsOsVY9QAZnZW20+MBdYWGKB3NJg==", 'sha3_512 (digest_data_b64/1)');
is( digest_data_b64u('SHA3_512', ""), "pp9zzKI6msXItWfcGFp1bpfJghZP4lhZ4NHcwUdcgKYVshI68fX5TBHj6UAsOsVY9QAZnZW20-MBdYWGKB3NJg", 'sha3_512 (digest_data_b64u/1)');
is( Crypt::Digest::SHA3_512->new->add("")->hexdigest, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26", 'sha3_512 (OO/1)');

is( sha3_512("123"), pack("H*","48c8947f69c054a5caa934674ce8881d02bb18fb59d5a63eeaddff735b0e9801e87294783281ae49fc8287a0fd86779b27d7972d3e84f0fa0d826d7cb67dfefc"), 'sha3_512 (raw/2)');
is( sha3_512_hex("123"), "48c8947f69c054a5caa934674ce8881d02bb18fb59d5a63eeaddff735b0e9801e87294783281ae49fc8287a0fd86779b27d7972d3e84f0fa0d826d7cb67dfefc", 'sha3_512 (hex/2)');
is( sha3_512_b64("123"), "SMiUf2nAVKXKqTRnTOiIHQK7GPtZ1aY+6t3/c1sOmAHocpR4MoGuSfyCh6D9hnebJ9eXLT6E8PoNgm18tn3+/A==", 'sha3_512 (base64/2)');
is( digest_data('SHA3_512', "123"), pack("H*","48c8947f69c054a5caa934674ce8881d02bb18fb59d5a63eeaddff735b0e9801e87294783281ae49fc8287a0fd86779b27d7972d3e84f0fa0d826d7cb67dfefc"), 'sha3_512 (digest_data_raw/2)');
is( digest_data_hex('SHA3_512', "123"), "48c8947f69c054a5caa934674ce8881d02bb18fb59d5a63eeaddff735b0e9801e87294783281ae49fc8287a0fd86779b27d7972d3e84f0fa0d826d7cb67dfefc", 'sha3_512 (digest_data_hex/2)');
is( digest_data_b64('SHA3_512', "123"), "SMiUf2nAVKXKqTRnTOiIHQK7GPtZ1aY+6t3/c1sOmAHocpR4MoGuSfyCh6D9hnebJ9eXLT6E8PoNgm18tn3+/A==", 'sha3_512 (digest_data_b64/2)');
is( digest_data_b64u('SHA3_512', "123"), "SMiUf2nAVKXKqTRnTOiIHQK7GPtZ1aY-6t3_c1sOmAHocpR4MoGuSfyCh6D9hnebJ9eXLT6E8PoNgm18tn3-_A", 'sha3_512 (digest_data_b64u/2)');
is( Crypt::Digest::SHA3_512->new->add("123")->hexdigest, "48c8947f69c054a5caa934674ce8881d02bb18fb59d5a63eeaddff735b0e9801e87294783281ae49fc8287a0fd86779b27d7972d3e84f0fa0d826d7cb67dfefc", 'sha3_512 (OO/2)');

is( sha3_512("test\0test\0test\n"), pack("H*","32ae141bb6ed097396f3258e2d4d5b9d03901a1fd09b82ab753027d3f6806763cc50daa3c50ab077e2acb0b792995cb3b539e6ec0171e56b9c6635780e79f693"), 'sha3_512 (raw/3)');
is( sha3_512_hex("test\0test\0test\n"), "32ae141bb6ed097396f3258e2d4d5b9d03901a1fd09b82ab753027d3f6806763cc50daa3c50ab077e2acb0b792995cb3b539e6ec0171e56b9c6635780e79f693", 'sha3_512 (hex/3)');
is( sha3_512_b64("test\0test\0test\n"), "Mq4UG7btCXOW8yWOLU1bnQOQGh/Qm4KrdTAn0/aAZ2PMUNqjxQqwd+KssLeSmVyztTnm7AFx5WucZjV4Dnn2kw==", 'sha3_512 (base64/3)');
is( digest_data('SHA3_512', "test\0test\0test\n"), pack("H*","32ae141bb6ed097396f3258e2d4d5b9d03901a1fd09b82ab753027d3f6806763cc50daa3c50ab077e2acb0b792995cb3b539e6ec0171e56b9c6635780e79f693"), 'sha3_512 (digest_data_raw/3)');
is( digest_data_hex('SHA3_512', "test\0test\0test\n"), "32ae141bb6ed097396f3258e2d4d5b9d03901a1fd09b82ab753027d3f6806763cc50daa3c50ab077e2acb0b792995cb3b539e6ec0171e56b9c6635780e79f693", 'sha3_512 (digest_data_hex/3)');
is( digest_data_b64('SHA3_512', "test\0test\0test\n"), "Mq4UG7btCXOW8yWOLU1bnQOQGh/Qm4KrdTAn0/aAZ2PMUNqjxQqwd+KssLeSmVyztTnm7AFx5WucZjV4Dnn2kw==", 'sha3_512 (digest_data_b64/3)');
is( digest_data_b64u('SHA3_512', "test\0test\0test\n"), "Mq4UG7btCXOW8yWOLU1bnQOQGh_Qm4KrdTAn0_aAZ2PMUNqjxQqwd-KssLeSmVyztTnm7AFx5WucZjV4Dnn2kw", 'sha3_512 (digest_data_b64u/3)');
is( Crypt::Digest::SHA3_512->new->add("test\0test\0test\n")->hexdigest, "32ae141bb6ed097396f3258e2d4d5b9d03901a1fd09b82ab753027d3f6806763cc50daa3c50ab077e2acb0b792995cb3b539e6ec0171e56b9c6635780e79f693", 'sha3_512 (OO/3)');


is( sha3_512_file('t/data/binary-test.file'), pack("H*","1ac54b7f8bb2e36b90e796fc6435e5a5e97e4884e3e85c75eb51a0c45724843e63a508adc0ffaf3c9998e23de6b38c6293a8deaf9467a6b512b28c38f2801cef"), 'sha3_512 (raw/file/1)');
is( sha3_512_file_hex('t/data/binary-test.file'), "1ac54b7f8bb2e36b90e796fc6435e5a5e97e4884e3e85c75eb51a0c45724843e63a508adc0ffaf3c9998e23de6b38c6293a8deaf9467a6b512b28c38f2801cef", 'sha3_512 (hex/file/1)');
is( sha3_512_file_b64('t/data/binary-test.file'), "GsVLf4uy42uQ55b8ZDXlpel+SITj6Fx161GgxFckhD5jpQitwP+vPJmY4j3ms4xik6jer5RnprUSsow48oAc7w==", 'sha3_512 (base64/file/1)');
is( digest_file('SHA3_512', 't/data/binary-test.file'), pack("H*","1ac54b7f8bb2e36b90e796fc6435e5a5e97e4884e3e85c75eb51a0c45724843e63a508adc0ffaf3c9998e23de6b38c6293a8deaf9467a6b512b28c38f2801cef"), 'sha3_512 (digest_file_raw/file/1)');
is( digest_file_hex('SHA3_512', 't/data/binary-test.file'), "1ac54b7f8bb2e36b90e796fc6435e5a5e97e4884e3e85c75eb51a0c45724843e63a508adc0ffaf3c9998e23de6b38c6293a8deaf9467a6b512b28c38f2801cef", 'sha3_512 (digest_file_hex/file/1)');
is( digest_file_b64('SHA3_512', 't/data/binary-test.file'), "GsVLf4uy42uQ55b8ZDXlpel+SITj6Fx161GgxFckhD5jpQitwP+vPJmY4j3ms4xik6jer5RnprUSsow48oAc7w==", 'sha3_512 (digest_file_b64/file/1)');
is( digest_file_b64u('SHA3_512', 't/data/binary-test.file'), "GsVLf4uy42uQ55b8ZDXlpel-SITj6Fx161GgxFckhD5jpQitwP-vPJmY4j3ms4xik6jer5RnprUSsow48oAc7w", 'sha3_512 (digest_file_b64u/file/1)');
is( Crypt::Digest::SHA3_512->new->addfile('t/data/binary-test.file')->hexdigest, "1ac54b7f8bb2e36b90e796fc6435e5a5e97e4884e3e85c75eb51a0c45724843e63a508adc0ffaf3c9998e23de6b38c6293a8deaf9467a6b512b28c38f2801cef", 'sha3_512 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_512->new->addfile($fh)->hexdigest, "1ac54b7f8bb2e36b90e796fc6435e5a5e97e4884e3e85c75eb51a0c45724843e63a508adc0ffaf3c9998e23de6b38c6293a8deaf9467a6b512b28c38f2801cef", 'sha3_512 (OO/filehandle/1)');
  close($fh);
}

is( sha3_512_file('t/data/text-CR.file'), pack("H*","2537d084e27c839299a76b7f54e786f13eba94030c4adc5b254106212d2e1db2e6dd2bea0d785e6b3561713fb1677d28a5ec914c9d5360145606054b6576e0c1"), 'sha3_512 (raw/file/2)');
is( sha3_512_file_hex('t/data/text-CR.file'), "2537d084e27c839299a76b7f54e786f13eba94030c4adc5b254106212d2e1db2e6dd2bea0d785e6b3561713fb1677d28a5ec914c9d5360145606054b6576e0c1", 'sha3_512 (hex/file/2)');
is( sha3_512_file_b64('t/data/text-CR.file'), "JTfQhOJ8g5KZp2t/VOeG8T66lAMMStxbJUEGIS0uHbLm3SvqDXheazVhcT+xZ30opeyRTJ1TYBRWBgVLZXbgwQ==", 'sha3_512 (base64/file/2)');
is( digest_file('SHA3_512', 't/data/text-CR.file'), pack("H*","2537d084e27c839299a76b7f54e786f13eba94030c4adc5b254106212d2e1db2e6dd2bea0d785e6b3561713fb1677d28a5ec914c9d5360145606054b6576e0c1"), 'sha3_512 (digest_file_raw/file/2)');
is( digest_file_hex('SHA3_512', 't/data/text-CR.file'), "2537d084e27c839299a76b7f54e786f13eba94030c4adc5b254106212d2e1db2e6dd2bea0d785e6b3561713fb1677d28a5ec914c9d5360145606054b6576e0c1", 'sha3_512 (digest_file_hex/file/2)');
is( digest_file_b64('SHA3_512', 't/data/text-CR.file'), "JTfQhOJ8g5KZp2t/VOeG8T66lAMMStxbJUEGIS0uHbLm3SvqDXheazVhcT+xZ30opeyRTJ1TYBRWBgVLZXbgwQ==", 'sha3_512 (digest_file_b64/file/2)');
is( digest_file_b64u('SHA3_512', 't/data/text-CR.file'), "JTfQhOJ8g5KZp2t_VOeG8T66lAMMStxbJUEGIS0uHbLm3SvqDXheazVhcT-xZ30opeyRTJ1TYBRWBgVLZXbgwQ", 'sha3_512 (digest_file_b64u/file/2)');
is( Crypt::Digest::SHA3_512->new->addfile('t/data/text-CR.file')->hexdigest, "2537d084e27c839299a76b7f54e786f13eba94030c4adc5b254106212d2e1db2e6dd2bea0d785e6b3561713fb1677d28a5ec914c9d5360145606054b6576e0c1", 'sha3_512 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_512->new->addfile($fh)->hexdigest, "2537d084e27c839299a76b7f54e786f13eba94030c4adc5b254106212d2e1db2e6dd2bea0d785e6b3561713fb1677d28a5ec914c9d5360145606054b6576e0c1", 'sha3_512 (OO/filehandle/2)');
  close($fh);
}

is( sha3_512_file('t/data/text-CRLF.file'), pack("H*","2fceadea90f637c1e09802d9d4bb0799b95c17d51eff2e8db118d1f6fced01f43bdee512d4d6bf58727debcb80331a9939b683cf30496af67aa3095b517f11ed"), 'sha3_512 (raw/file/3)');
is( sha3_512_file_hex('t/data/text-CRLF.file'), "2fceadea90f637c1e09802d9d4bb0799b95c17d51eff2e8db118d1f6fced01f43bdee512d4d6bf58727debcb80331a9939b683cf30496af67aa3095b517f11ed", 'sha3_512 (hex/file/3)');
is( sha3_512_file_b64('t/data/text-CRLF.file'), "L86t6pD2N8HgmALZ1LsHmblcF9Ue/y6NsRjR9vztAfQ73uUS1Na/WHJ968uAMxqZObaDzzBJavZ6owlbUX8R7Q==", 'sha3_512 (base64/file/3)');
is( digest_file('SHA3_512', 't/data/text-CRLF.file'), pack("H*","2fceadea90f637c1e09802d9d4bb0799b95c17d51eff2e8db118d1f6fced01f43bdee512d4d6bf58727debcb80331a9939b683cf30496af67aa3095b517f11ed"), 'sha3_512 (digest_file_raw/file/3)');
is( digest_file_hex('SHA3_512', 't/data/text-CRLF.file'), "2fceadea90f637c1e09802d9d4bb0799b95c17d51eff2e8db118d1f6fced01f43bdee512d4d6bf58727debcb80331a9939b683cf30496af67aa3095b517f11ed", 'sha3_512 (digest_file_hex/file/3)');
is( digest_file_b64('SHA3_512', 't/data/text-CRLF.file'), "L86t6pD2N8HgmALZ1LsHmblcF9Ue/y6NsRjR9vztAfQ73uUS1Na/WHJ968uAMxqZObaDzzBJavZ6owlbUX8R7Q==", 'sha3_512 (digest_file_b64/file/3)');
is( digest_file_b64u('SHA3_512', 't/data/text-CRLF.file'), "L86t6pD2N8HgmALZ1LsHmblcF9Ue_y6NsRjR9vztAfQ73uUS1Na_WHJ968uAMxqZObaDzzBJavZ6owlbUX8R7Q", 'sha3_512 (digest_file_b64u/file/3)');
is( Crypt::Digest::SHA3_512->new->addfile('t/data/text-CRLF.file')->hexdigest, "2fceadea90f637c1e09802d9d4bb0799b95c17d51eff2e8db118d1f6fced01f43bdee512d4d6bf58727debcb80331a9939b683cf30496af67aa3095b517f11ed", 'sha3_512 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_512->new->addfile($fh)->hexdigest, "2fceadea90f637c1e09802d9d4bb0799b95c17d51eff2e8db118d1f6fced01f43bdee512d4d6bf58727debcb80331a9939b683cf30496af67aa3095b517f11ed", 'sha3_512 (OO/filehandle/3)');
  close($fh);
}

is( sha3_512_file('t/data/text-LF.file'), pack("H*","46e2ef6af9a108abc49d692ca06ec20b136b96cfa0c4dbb9ecfce7d02c5712dbb2cd5f7e8a84b3ff15465e50d1ec6caffe5212749d96a3468e3477c3da877282"), 'sha3_512 (raw/file/4)');
is( sha3_512_file_hex('t/data/text-LF.file'), "46e2ef6af9a108abc49d692ca06ec20b136b96cfa0c4dbb9ecfce7d02c5712dbb2cd5f7e8a84b3ff15465e50d1ec6caffe5212749d96a3468e3477c3da877282", 'sha3_512 (hex/file/4)');
is( sha3_512_file_b64('t/data/text-LF.file'), "RuLvavmhCKvEnWksoG7CCxNrls+gxNu57Pzn0CxXEtuyzV9+ioSz/xVGXlDR7Gyv/lISdJ2Wo0aONHfD2odygg==", 'sha3_512 (base64/file/4)');
is( digest_file('SHA3_512', 't/data/text-LF.file'), pack("H*","46e2ef6af9a108abc49d692ca06ec20b136b96cfa0c4dbb9ecfce7d02c5712dbb2cd5f7e8a84b3ff15465e50d1ec6caffe5212749d96a3468e3477c3da877282"), 'sha3_512 (digest_file_raw/file/4)');
is( digest_file_hex('SHA3_512', 't/data/text-LF.file'), "46e2ef6af9a108abc49d692ca06ec20b136b96cfa0c4dbb9ecfce7d02c5712dbb2cd5f7e8a84b3ff15465e50d1ec6caffe5212749d96a3468e3477c3da877282", 'sha3_512 (digest_file_hex/file/4)');
is( digest_file_b64('SHA3_512', 't/data/text-LF.file'), "RuLvavmhCKvEnWksoG7CCxNrls+gxNu57Pzn0CxXEtuyzV9+ioSz/xVGXlDR7Gyv/lISdJ2Wo0aONHfD2odygg==", 'sha3_512 (digest_file_b64/file/4)');
is( digest_file_b64u('SHA3_512', 't/data/text-LF.file'), "RuLvavmhCKvEnWksoG7CCxNrls-gxNu57Pzn0CxXEtuyzV9-ioSz_xVGXlDR7Gyv_lISdJ2Wo0aONHfD2odygg", 'sha3_512 (digest_file_b64u/file/4)');
is( Crypt::Digest::SHA3_512->new->addfile('t/data/text-LF.file')->hexdigest, "46e2ef6af9a108abc49d692ca06ec20b136b96cfa0c4dbb9ecfce7d02c5712dbb2cd5f7e8a84b3ff15465e50d1ec6caffe5212749d96a3468e3477c3da877282", 'sha3_512 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_512->new->addfile($fh)->hexdigest, "46e2ef6af9a108abc49d692ca06ec20b136b96cfa0c4dbb9ecfce7d02c5712dbb2cd5f7e8a84b3ff15465e50d1ec6caffe5212749d96a3468e3477c3da877282", 'sha3_512 (OO/filehandle/4)');
  close($fh);
}
