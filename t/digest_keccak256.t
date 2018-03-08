### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::Keccak256 qw( keccak256 keccak256_hex keccak256_b64 keccak256_b64u keccak256_file keccak256_file_hex keccak256_file_b64 keccak256_file_b64u );

is( Crypt::Digest::hashsize('Keccak256'), 32, 'hashsize/1');
is( Crypt::Digest->hashsize('Keccak256'), 32, 'hashsize/2');
is( Crypt::Digest::Keccak256::hashsize, 32, 'hashsize/3');
is( Crypt::Digest::Keccak256->hashsize, 32, 'hashsize/4');
is( Crypt::Digest->new('Keccak256')->hashsize, 32, 'hashsize/5');
is( Crypt::Digest::Keccak256->new->hashsize, 32, 'hashsize/6');

is( keccak256("A","A","A"), pack("H*","2070504003a07b4713d783ae7a6642ab3b959b7c575c6e4fa4f33eb743db631a"), 'keccak256 (raw/tripple_A)');
is( keccak256_hex("A","A","A"), "2070504003a07b4713d783ae7a6642ab3b959b7c575c6e4fa4f33eb743db631a", 'keccak256 (hex/tripple_A)');
is( keccak256_b64("A","A","A"), "IHBQQAOge0cT14OuemZCqzuVm3xXXG5PpPM+t0PbYxo=", 'keccak256 (base64/tripple_A)');
is( keccak256_b64u("A","A","A"), "IHBQQAOge0cT14OuemZCqzuVm3xXXG5PpPM-t0PbYxo", 'keccak256 (base64url/tripple_A)');
is( digest_data('Keccak256', "A","A","A"), pack("H*","2070504003a07b4713d783ae7a6642ab3b959b7c575c6e4fa4f33eb743db631a"), 'keccak256 (digest_data_raw/tripple_A)');
is( digest_data_hex('Keccak256', "A","A","A"), "2070504003a07b4713d783ae7a6642ab3b959b7c575c6e4fa4f33eb743db631a", 'keccak256 (digest_data_hex/tripple_A)');
is( digest_data_b64('Keccak256', "A","A","A"), "IHBQQAOge0cT14OuemZCqzuVm3xXXG5PpPM+t0PbYxo=", 'keccak256 (digest_data_b64/tripple_A)');
is( digest_data_b64u('Keccak256', "A","A","A"), "IHBQQAOge0cT14OuemZCqzuVm3xXXG5PpPM-t0PbYxo", 'keccak256 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::Keccak256->new->add("A","A","A")->hexdigest, "2070504003a07b4713d783ae7a6642ab3b959b7c575c6e4fa4f33eb743db631a", 'keccak256 (OO/tripple_A)');
is( Crypt::Digest::Keccak256->new->add("A")->add("A")->add("A")->hexdigest, "2070504003a07b4713d783ae7a6642ab3b959b7c575c6e4fa4f33eb743db631a", 'keccak256 (OO3/tripple_A)');


is( keccak256(""), pack("H*","c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), 'keccak256 (raw/1)');
is( keccak256_hex(""), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", 'keccak256 (hex/1)');
is( keccak256_b64(""), "xdJGAYb3IzySfn2y3McDwOUAtlPKgic7e/rYBF2FpHA=", 'keccak256 (base64/1)');
is( digest_data('Keccak256', ""), pack("H*","c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), 'keccak256 (digest_data_raw/1)');
is( digest_data_hex('Keccak256', ""), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", 'keccak256 (digest_data_hex/1)');
is( digest_data_b64('Keccak256', ""), "xdJGAYb3IzySfn2y3McDwOUAtlPKgic7e/rYBF2FpHA=", 'keccak256 (digest_data_b64/1)');
is( digest_data_b64u('Keccak256', ""), "xdJGAYb3IzySfn2y3McDwOUAtlPKgic7e_rYBF2FpHA", 'keccak256 (digest_data_b64u/1)');
is( Crypt::Digest::Keccak256->new->add("")->hexdigest, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", 'keccak256 (OO/1)');

is( keccak256("123"), pack("H*","64e604787cbf194841e7b68d7cd28786f6c9a0a3ab9f8b0a0e87cb4387ab0107"), 'keccak256 (raw/2)');
is( keccak256_hex("123"), "64e604787cbf194841e7b68d7cd28786f6c9a0a3ab9f8b0a0e87cb4387ab0107", 'keccak256 (hex/2)');
is( keccak256_b64("123"), "ZOYEeHy/GUhB57aNfNKHhvbJoKOrn4sKDofLQ4erAQc=", 'keccak256 (base64/2)');
is( digest_data('Keccak256', "123"), pack("H*","64e604787cbf194841e7b68d7cd28786f6c9a0a3ab9f8b0a0e87cb4387ab0107"), 'keccak256 (digest_data_raw/2)');
is( digest_data_hex('Keccak256', "123"), "64e604787cbf194841e7b68d7cd28786f6c9a0a3ab9f8b0a0e87cb4387ab0107", 'keccak256 (digest_data_hex/2)');
is( digest_data_b64('Keccak256', "123"), "ZOYEeHy/GUhB57aNfNKHhvbJoKOrn4sKDofLQ4erAQc=", 'keccak256 (digest_data_b64/2)');
is( digest_data_b64u('Keccak256', "123"), "ZOYEeHy_GUhB57aNfNKHhvbJoKOrn4sKDofLQ4erAQc", 'keccak256 (digest_data_b64u/2)');
is( Crypt::Digest::Keccak256->new->add("123")->hexdigest, "64e604787cbf194841e7b68d7cd28786f6c9a0a3ab9f8b0a0e87cb4387ab0107", 'keccak256 (OO/2)');

is( keccak256("test\0test\0test\n"), pack("H*","fbc121310d505fb7172a28e0e9e8c7d2976c9f63a739fe60bc298467bc72bb86"), 'keccak256 (raw/3)');
is( keccak256_hex("test\0test\0test\n"), "fbc121310d505fb7172a28e0e9e8c7d2976c9f63a739fe60bc298467bc72bb86", 'keccak256 (hex/3)');
is( keccak256_b64("test\0test\0test\n"), "+8EhMQ1QX7cXKijg6ejH0pdsn2OnOf5gvCmEZ7xyu4Y=", 'keccak256 (base64/3)');
is( digest_data('Keccak256', "test\0test\0test\n"), pack("H*","fbc121310d505fb7172a28e0e9e8c7d2976c9f63a739fe60bc298467bc72bb86"), 'keccak256 (digest_data_raw/3)');
is( digest_data_hex('Keccak256', "test\0test\0test\n"), "fbc121310d505fb7172a28e0e9e8c7d2976c9f63a739fe60bc298467bc72bb86", 'keccak256 (digest_data_hex/3)');
is( digest_data_b64('Keccak256', "test\0test\0test\n"), "+8EhMQ1QX7cXKijg6ejH0pdsn2OnOf5gvCmEZ7xyu4Y=", 'keccak256 (digest_data_b64/3)');
is( digest_data_b64u('Keccak256', "test\0test\0test\n"), "-8EhMQ1QX7cXKijg6ejH0pdsn2OnOf5gvCmEZ7xyu4Y", 'keccak256 (digest_data_b64u/3)');
is( Crypt::Digest::Keccak256->new->add("test\0test\0test\n")->hexdigest, "fbc121310d505fb7172a28e0e9e8c7d2976c9f63a739fe60bc298467bc72bb86", 'keccak256 (OO/3)');


is( keccak256_file('t/data/binary-test.file'), pack("H*","7046f5fad76cf793a1f44c159b656277ada3f428057ac8160d04fdcdc5b0fcb8"), 'keccak256 (raw/file/1)');
is( keccak256_file_hex('t/data/binary-test.file'), "7046f5fad76cf793a1f44c159b656277ada3f428057ac8160d04fdcdc5b0fcb8", 'keccak256 (hex/file/1)');
is( keccak256_file_b64('t/data/binary-test.file'), "cEb1+tds95Oh9EwVm2Vid62j9CgFesgWDQT9zcWw/Lg=", 'keccak256 (base64/file/1)');
is( digest_file('Keccak256', 't/data/binary-test.file'), pack("H*","7046f5fad76cf793a1f44c159b656277ada3f428057ac8160d04fdcdc5b0fcb8"), 'keccak256 (digest_file_raw/file/1)');
is( digest_file_hex('Keccak256', 't/data/binary-test.file'), "7046f5fad76cf793a1f44c159b656277ada3f428057ac8160d04fdcdc5b0fcb8", 'keccak256 (digest_file_hex/file/1)');
is( digest_file_b64('Keccak256', 't/data/binary-test.file'), "cEb1+tds95Oh9EwVm2Vid62j9CgFesgWDQT9zcWw/Lg=", 'keccak256 (digest_file_b64/file/1)');
is( digest_file_b64u('Keccak256', 't/data/binary-test.file'), "cEb1-tds95Oh9EwVm2Vid62j9CgFesgWDQT9zcWw_Lg", 'keccak256 (digest_file_b64u/file/1)');
is( Crypt::Digest::Keccak256->new->addfile('t/data/binary-test.file')->hexdigest, "7046f5fad76cf793a1f44c159b656277ada3f428057ac8160d04fdcdc5b0fcb8", 'keccak256 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::Keccak256->new->addfile($fh)->hexdigest, "7046f5fad76cf793a1f44c159b656277ada3f428057ac8160d04fdcdc5b0fcb8", 'keccak256 (OO/filehandle/1)');
  close($fh);
}

is( keccak256_file('t/data/text-CR.file'), pack("H*","288d47897222a6fbd6d8593cd06796e6c3eb5637a6eaf8fc033dc9243ce01c18"), 'keccak256 (raw/file/2)');
is( keccak256_file_hex('t/data/text-CR.file'), "288d47897222a6fbd6d8593cd06796e6c3eb5637a6eaf8fc033dc9243ce01c18", 'keccak256 (hex/file/2)');
is( keccak256_file_b64('t/data/text-CR.file'), "KI1HiXIipvvW2Fk80GeW5sPrVjem6vj8Az3JJDzgHBg=", 'keccak256 (base64/file/2)');
is( digest_file('Keccak256', 't/data/text-CR.file'), pack("H*","288d47897222a6fbd6d8593cd06796e6c3eb5637a6eaf8fc033dc9243ce01c18"), 'keccak256 (digest_file_raw/file/2)');
is( digest_file_hex('Keccak256', 't/data/text-CR.file'), "288d47897222a6fbd6d8593cd06796e6c3eb5637a6eaf8fc033dc9243ce01c18", 'keccak256 (digest_file_hex/file/2)');
is( digest_file_b64('Keccak256', 't/data/text-CR.file'), "KI1HiXIipvvW2Fk80GeW5sPrVjem6vj8Az3JJDzgHBg=", 'keccak256 (digest_file_b64/file/2)');
is( digest_file_b64u('Keccak256', 't/data/text-CR.file'), "KI1HiXIipvvW2Fk80GeW5sPrVjem6vj8Az3JJDzgHBg", 'keccak256 (digest_file_b64u/file/2)');
is( Crypt::Digest::Keccak256->new->addfile('t/data/text-CR.file')->hexdigest, "288d47897222a6fbd6d8593cd06796e6c3eb5637a6eaf8fc033dc9243ce01c18", 'keccak256 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::Keccak256->new->addfile($fh)->hexdigest, "288d47897222a6fbd6d8593cd06796e6c3eb5637a6eaf8fc033dc9243ce01c18", 'keccak256 (OO/filehandle/2)');
  close($fh);
}

is( keccak256_file('t/data/text-CRLF.file'), pack("H*","a44703b85d5ee7f35b3c0c21c646d695978d0ec5ea36a1a05a77427c5f964ee1"), 'keccak256 (raw/file/3)');
is( keccak256_file_hex('t/data/text-CRLF.file'), "a44703b85d5ee7f35b3c0c21c646d695978d0ec5ea36a1a05a77427c5f964ee1", 'keccak256 (hex/file/3)');
is( keccak256_file_b64('t/data/text-CRLF.file'), "pEcDuF1e5/NbPAwhxkbWlZeNDsXqNqGgWndCfF+WTuE=", 'keccak256 (base64/file/3)');
is( digest_file('Keccak256', 't/data/text-CRLF.file'), pack("H*","a44703b85d5ee7f35b3c0c21c646d695978d0ec5ea36a1a05a77427c5f964ee1"), 'keccak256 (digest_file_raw/file/3)');
is( digest_file_hex('Keccak256', 't/data/text-CRLF.file'), "a44703b85d5ee7f35b3c0c21c646d695978d0ec5ea36a1a05a77427c5f964ee1", 'keccak256 (digest_file_hex/file/3)');
is( digest_file_b64('Keccak256', 't/data/text-CRLF.file'), "pEcDuF1e5/NbPAwhxkbWlZeNDsXqNqGgWndCfF+WTuE=", 'keccak256 (digest_file_b64/file/3)');
is( digest_file_b64u('Keccak256', 't/data/text-CRLF.file'), "pEcDuF1e5_NbPAwhxkbWlZeNDsXqNqGgWndCfF-WTuE", 'keccak256 (digest_file_b64u/file/3)');
is( Crypt::Digest::Keccak256->new->addfile('t/data/text-CRLF.file')->hexdigest, "a44703b85d5ee7f35b3c0c21c646d695978d0ec5ea36a1a05a77427c5f964ee1", 'keccak256 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::Keccak256->new->addfile($fh)->hexdigest, "a44703b85d5ee7f35b3c0c21c646d695978d0ec5ea36a1a05a77427c5f964ee1", 'keccak256 (OO/filehandle/3)');
  close($fh);
}

is( keccak256_file('t/data/text-LF.file'), pack("H*","188476c71de2afcb7eda9dbc560b5eb5e4e681a558568a41068eb6d738efa4f4"), 'keccak256 (raw/file/4)');
is( keccak256_file_hex('t/data/text-LF.file'), "188476c71de2afcb7eda9dbc560b5eb5e4e681a558568a41068eb6d738efa4f4", 'keccak256 (hex/file/4)');
is( keccak256_file_b64('t/data/text-LF.file'), "GIR2xx3ir8t+2p28VgteteTmgaVYVopBBo621zjvpPQ=", 'keccak256 (base64/file/4)');
is( digest_file('Keccak256', 't/data/text-LF.file'), pack("H*","188476c71de2afcb7eda9dbc560b5eb5e4e681a558568a41068eb6d738efa4f4"), 'keccak256 (digest_file_raw/file/4)');
is( digest_file_hex('Keccak256', 't/data/text-LF.file'), "188476c71de2afcb7eda9dbc560b5eb5e4e681a558568a41068eb6d738efa4f4", 'keccak256 (digest_file_hex/file/4)');
is( digest_file_b64('Keccak256', 't/data/text-LF.file'), "GIR2xx3ir8t+2p28VgteteTmgaVYVopBBo621zjvpPQ=", 'keccak256 (digest_file_b64/file/4)');
is( digest_file_b64u('Keccak256', 't/data/text-LF.file'), "GIR2xx3ir8t-2p28VgteteTmgaVYVopBBo621zjvpPQ", 'keccak256 (digest_file_b64u/file/4)');
is( Crypt::Digest::Keccak256->new->addfile('t/data/text-LF.file')->hexdigest, "188476c71de2afcb7eda9dbc560b5eb5e4e681a558568a41068eb6d738efa4f4", 'keccak256 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::Keccak256->new->addfile($fh)->hexdigest, "188476c71de2afcb7eda9dbc560b5eb5e4e681a558568a41068eb6d738efa4f4", 'keccak256 (OO/filehandle/4)');
  close($fh);
}
