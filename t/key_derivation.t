use strict;
use warnings;
use Test::More tests => 27;

use Crypt::KeyDerivation qw(pbkdf1 pbkdf2 hkdf hkdf_expand hkdf_extract);

{ ### rfc5869 test case 1
  my $keying_material = pack("H*", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  my $salt = pack("H*", "000102030405060708090a0b0c");
  my $info = pack("H*", "f0f1f2f3f4f5f6f7f8f9");
  my $len = 42;
  my $hash_name = 'SHA256';
  my $expected_prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
  my $expected_okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

  my $prk  = hkdf_extract($keying_material, $salt, $hash_name);
  my $okm1 = hkdf_expand($prk, $hash_name, $len, $info);
  my $okm2 = hkdf($keying_material, $salt, $hash_name, $len, $info);
  is(unpack("H*", $prk),  $expected_prk, "PRK hkdf_extract/1");
  is(unpack("H*", $okm1), $expected_okm, "OKM1 hkdf_expand/1");
  is(unpack("H*", $okm2), $expected_okm, "OKM2 hkdf/1");
}

{ ### rfc5869 test case 2
  my $keying_material = pack("H*", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
  my $salt = pack("H*", "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
  my $info = pack("H*", "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
  my $len = 82;
  my $hash_name = 'SHA256';
  my $expected_prk = "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244";
  my $expected_okm = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87";

  my $prk  = hkdf_extract($keying_material, $salt, $hash_name);
  my $okm1 = hkdf_expand($prk, $hash_name, $len, $info);
  my $okm2 = hkdf($keying_material, $salt, $hash_name, $len, $info);
  is(unpack("H*", $prk),  $expected_prk, "PRK hkdf_extract/2");
  is(unpack("H*", $okm1), $expected_okm, "OKM1 hkdf_expand/2");
  is(unpack("H*", $okm2), $expected_okm, "OKM2 hkdf/2");
}

{ ### rfc5869 test case 3
  my $keying_material = pack("H*", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  my $salt = '';
  my $info = '';
  my $len = 42;
  my $hash_name = 'SHA256';
  my $expected_prk = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04";
  my $expected_okm = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";

  my $prk  = hkdf_extract($keying_material, $salt, $hash_name);
  my $okm1 = hkdf_expand($prk, $hash_name, $len, $info);
  my $okm2 = hkdf($keying_material, $salt, $hash_name, $len, $info);
  is(unpack("H*", $prk),  $expected_prk, "PRK hkdf_extract/3");
  is(unpack("H*", $okm1), $expected_okm, "OKM1 hkdf_expand/3");
  is(unpack("H*", $okm2), $expected_okm, "OKM2 hkdf/3");
}

{ ### rfc5869 test case 4
  my $keying_material = pack("H*", "0b0b0b0b0b0b0b0b0b0b0b");
  my $salt = pack("H*", "000102030405060708090a0b0c");
  my $info = pack("H*", "f0f1f2f3f4f5f6f7f8f9");
  my $len = 42;
  my $hash_name = 'SHA1';
  my $expected_prk = "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243";
  my $expected_okm = "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896";

  my $prk  = hkdf_extract($keying_material, $salt, $hash_name);
  my $okm1 = hkdf_expand($prk, $hash_name, $len, $info);
  my $okm2 = hkdf($keying_material, $salt, $hash_name, $len, $info);
  is(unpack("H*", $prk),  $expected_prk, "PRK hkdf_extract/4");
  is(unpack("H*", $okm1), $expected_okm, "OKM1 hkdf_expand/4");
  is(unpack("H*", $okm2), $expected_okm, "OKM2 hkdf/4");
}

{ ### rfc5869 test case 5
  my $keying_material = pack("H*", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
  my $salt = pack("H*", "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
  my $info = pack("H*", "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
  my $len = 82;
  my $hash_name = 'SHA1';
  my $expected_prk = "8adae09a2a307059478d309b26c4115a224cfaf6";
  my $expected_okm = "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4";

  my $prk  = hkdf_extract($keying_material, $salt, $hash_name);
  my $okm1 = hkdf_expand($prk, $hash_name, $len, $info);
  my $okm2 = hkdf($keying_material, $salt, $hash_name, $len, $info);
  is(unpack("H*", $prk),  $expected_prk, "PRK hkdf_extract/5");
  is(unpack("H*", $okm1), $expected_okm, "OKM1 hkdf_expand/5");
  is(unpack("H*", $okm2), $expected_okm, "OKM2 hkdf/5");
}

{ ### rfc5869 test case 6
  my $keying_material = pack("H*", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  my $salt = '';
  my $info = '';
  my $len = 42;
  my $hash_name = 'SHA1';
  my $expected_prk = "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01";
  my $expected_okm = "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918";

  my $prk  = hkdf_extract($keying_material, $salt, $hash_name);
  my $okm1 = hkdf_expand($prk, $hash_name, $len, $info);
  my $okm2 = hkdf($keying_material, $salt, $hash_name, $len, $info);
  is(unpack("H*", $prk),  $expected_prk, "PRK hkdf_extract/6");
  is(unpack("H*", $okm1), $expected_okm, "OKM1 hkdf_expand/6");
  is(unpack("H*", $okm2), $expected_okm, "OKM2 hkdf/6");
}

{ ### rfc5869 test case 7
  my $keying_material = pack("H*", "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
  my $salt = undef;
  my $info = '';
  my $len = 42;
  my $hash_name = 'SHA1';
  my $expected_prk = "2adccada18779e7c2077ad2eb19d3f3e731385dd";
  my $expected_okm = "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48";

  my $prk  = hkdf_extract($keying_material, $salt, $hash_name);
  my $okm1 = hkdf_expand($prk, $hash_name, $len, $info);
  my $okm2 = hkdf($keying_material, $salt, $hash_name, $len, $info);
  is(unpack("H*", $prk),  $expected_prk, "PRK hkdf_extract/7");
  is(unpack("H*", $okm1), $expected_okm, "OKM1 hkdf_expand/7");
  is(unpack("H*", $okm2), $expected_okm, "OKM2 hkdf/7");
}

{ #PBKDF1
  is(unpack('H*', pbkdf1(unpack("H*", "012345678910111231415161717"), unpack("H*", "F7560045C70A96DB"), 12, 'SHA1', 20)), '59a9c8a32646428e6724cc9f43c72aa69a6edc1f', 'test pbkdf1 A');
}

{ #PBKDF2 http://tools.ietf.org/html/rfc6070
  is(unpack('H*', pbkdf2("password", "salt", 1, 'SHA1', 20)),                                                     '0c60c80f961f0e71f3a9b524af6012062fe037a6', 'test pbkdf2 A');
  is(unpack('H*', pbkdf2("password", "salt", 2, 'SHA1', 20)),                                                     'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957', 'test pbkdf2 B');
  is(unpack('H*', pbkdf2("password", "salt", 4096, 'SHA1', 20)),                                                  '4b007901b765489abead49d926f721d065a429c1', 'test pbkdf2 C');
  ###LONG RUNNING###
  #is(unpack('H*', pbkdf2("password", "salt", 16777216, 'SHA1', 20)),                                              'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984', 'test pbkdf2 D');
  is(unpack('H*', pbkdf2("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 'SHA1', 25)),  '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038', 'test pbkdf2 E');
  is(unpack('H*', pbkdf2("pass\0word", "sa\0lt", 4096, 'SHA1', 16)),                                              '56fa6aa75548099dcc37d7f03425e0c3', 'test pbkdf2 F');
}
