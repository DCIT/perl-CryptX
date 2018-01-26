### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::SHA256 qw( sha256 sha256_hex sha256_b64 sha256_b64u sha256_file sha256_file_hex sha256_file_b64 sha256_file_b64u );

is( Crypt::Digest::hashsize('SHA256'), 32, 'hashsize/1');
is( Crypt::Digest->hashsize('SHA256'), 32, 'hashsize/2');
is( Crypt::Digest::SHA256::hashsize, 32, 'hashsize/3');
is( Crypt::Digest::SHA256->hashsize, 32, 'hashsize/4');
is( Crypt::Digest->new('SHA256')->hashsize, 32, 'hashsize/5');
is( Crypt::Digest::SHA256->new->hashsize, 32, 'hashsize/6');

is( sha256("A","A","A"), pack("H*","cb1ad2119d8fafb69566510ee712661f9f14b83385006ef92aec47f523a38358"), 'sha256 (raw/tripple_A)');
is( sha256_hex("A","A","A"), "cb1ad2119d8fafb69566510ee712661f9f14b83385006ef92aec47f523a38358", 'sha256 (hex/tripple_A)');
is( sha256_b64("A","A","A"), "yxrSEZ2Pr7aVZlEO5xJmH58UuDOFAG75KuxH9SOjg1g=", 'sha256 (base64/tripple_A)');
is( sha256_b64u("A","A","A"), "yxrSEZ2Pr7aVZlEO5xJmH58UuDOFAG75KuxH9SOjg1g", 'sha256 (base64url/tripple_A)');
is( digest_data('SHA256', "A","A","A"), pack("H*","cb1ad2119d8fafb69566510ee712661f9f14b83385006ef92aec47f523a38358"), 'sha256 (digest_data_raw/tripple_A)');
is( digest_data_hex('SHA256', "A","A","A"), "cb1ad2119d8fafb69566510ee712661f9f14b83385006ef92aec47f523a38358", 'sha256 (digest_data_hex/tripple_A)');
is( digest_data_b64('SHA256', "A","A","A"), "yxrSEZ2Pr7aVZlEO5xJmH58UuDOFAG75KuxH9SOjg1g=", 'sha256 (digest_data_b64/tripple_A)');
is( digest_data_b64u('SHA256', "A","A","A"), "yxrSEZ2Pr7aVZlEO5xJmH58UuDOFAG75KuxH9SOjg1g", 'sha256 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::SHA256->new->add("A","A","A")->hexdigest, "cb1ad2119d8fafb69566510ee712661f9f14b83385006ef92aec47f523a38358", 'sha256 (OO/tripple_A)');
is( Crypt::Digest::SHA256->new->add("A")->add("A")->add("A")->hexdigest, "cb1ad2119d8fafb69566510ee712661f9f14b83385006ef92aec47f523a38358", 'sha256 (OO3/tripple_A)');


is( sha256(""), pack("H*","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), 'sha256 (raw/1)');
is( sha256_hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 'sha256 (hex/1)');
is( sha256_b64(""), "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", 'sha256 (base64/1)');
is( digest_data('SHA256', ""), pack("H*","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), 'sha256 (digest_data_raw/1)');
is( digest_data_hex('SHA256', ""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 'sha256 (digest_data_hex/1)');
is( digest_data_b64('SHA256', ""), "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", 'sha256 (digest_data_b64/1)');
is( digest_data_b64u('SHA256', ""), "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", 'sha256 (digest_data_b64u/1)');
is( Crypt::Digest::SHA256->new->add("")->hexdigest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 'sha256 (OO/1)');

is( sha256("123"), pack("H*","a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"), 'sha256 (raw/2)');
is( sha256_hex("123"), "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", 'sha256 (hex/2)');
is( sha256_b64("123"), "pmWkWSBCL51Bfkhn79xPuKBKHz//H6B+mY6G9/eieuM=", 'sha256 (base64/2)');
is( digest_data('SHA256', "123"), pack("H*","a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"), 'sha256 (digest_data_raw/2)');
is( digest_data_hex('SHA256', "123"), "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", 'sha256 (digest_data_hex/2)');
is( digest_data_b64('SHA256', "123"), "pmWkWSBCL51Bfkhn79xPuKBKHz//H6B+mY6G9/eieuM=", 'sha256 (digest_data_b64/2)');
is( digest_data_b64u('SHA256', "123"), "pmWkWSBCL51Bfkhn79xPuKBKHz__H6B-mY6G9_eieuM", 'sha256 (digest_data_b64u/2)');
is( Crypt::Digest::SHA256->new->add("123")->hexdigest, "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", 'sha256 (OO/2)');

is( sha256("test\0test\0test\n"), pack("H*","6dedffd4eec5795dec92554802efd8b4a7abc7092f774597abc895c9bc528522"), 'sha256 (raw/3)');
is( sha256_hex("test\0test\0test\n"), "6dedffd4eec5795dec92554802efd8b4a7abc7092f774597abc895c9bc528522", 'sha256 (hex/3)');
is( sha256_b64("test\0test\0test\n"), "be3/1O7FeV3sklVIAu/YtKerxwkvd0WXq8iVybxShSI=", 'sha256 (base64/3)');
is( digest_data('SHA256', "test\0test\0test\n"), pack("H*","6dedffd4eec5795dec92554802efd8b4a7abc7092f774597abc895c9bc528522"), 'sha256 (digest_data_raw/3)');
is( digest_data_hex('SHA256', "test\0test\0test\n"), "6dedffd4eec5795dec92554802efd8b4a7abc7092f774597abc895c9bc528522", 'sha256 (digest_data_hex/3)');
is( digest_data_b64('SHA256', "test\0test\0test\n"), "be3/1O7FeV3sklVIAu/YtKerxwkvd0WXq8iVybxShSI=", 'sha256 (digest_data_b64/3)');
is( digest_data_b64u('SHA256', "test\0test\0test\n"), "be3_1O7FeV3sklVIAu_YtKerxwkvd0WXq8iVybxShSI", 'sha256 (digest_data_b64u/3)');
is( Crypt::Digest::SHA256->new->add("test\0test\0test\n")->hexdigest, "6dedffd4eec5795dec92554802efd8b4a7abc7092f774597abc895c9bc528522", 'sha256 (OO/3)');


is( sha256_file('t/data/binary-test.file'), pack("H*","eefc3172bcb45a8e99233f5f33faea312e50894885d9677d9ef530f734a3b343"), 'sha256 (raw/file/1)');
is( sha256_file_hex('t/data/binary-test.file'), "eefc3172bcb45a8e99233f5f33faea312e50894885d9677d9ef530f734a3b343", 'sha256 (hex/file/1)');
is( sha256_file_b64('t/data/binary-test.file'), "7vwxcry0Wo6ZIz9fM/rqMS5QiUiF2Wd9nvUw9zSjs0M=", 'sha256 (base64/file/1)');
is( digest_file('SHA256', 't/data/binary-test.file'), pack("H*","eefc3172bcb45a8e99233f5f33faea312e50894885d9677d9ef530f734a3b343"), 'sha256 (digest_file_raw/file/1)');
is( digest_file_hex('SHA256', 't/data/binary-test.file'), "eefc3172bcb45a8e99233f5f33faea312e50894885d9677d9ef530f734a3b343", 'sha256 (digest_file_hex/file/1)');
is( digest_file_b64('SHA256', 't/data/binary-test.file'), "7vwxcry0Wo6ZIz9fM/rqMS5QiUiF2Wd9nvUw9zSjs0M=", 'sha256 (digest_file_b64/file/1)');
is( digest_file_b64u('SHA256', 't/data/binary-test.file'), "7vwxcry0Wo6ZIz9fM_rqMS5QiUiF2Wd9nvUw9zSjs0M", 'sha256 (digest_file_b64u/file/1)');
is( Crypt::Digest::SHA256->new->addfile('t/data/binary-test.file')->hexdigest, "eefc3172bcb45a8e99233f5f33faea312e50894885d9677d9ef530f734a3b343", 'sha256 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::SHA256->new->addfile($fh)->hexdigest, "eefc3172bcb45a8e99233f5f33faea312e50894885d9677d9ef530f734a3b343", 'sha256 (OO/filehandle/1)');
  close($fh);
}

is( sha256_file('t/data/text-CR.file'), pack("H*","00e46d5084204a794818df06df45e7cc4489fd7ada4762c958b3c19c86409193"), 'sha256 (raw/file/2)');
is( sha256_file_hex('t/data/text-CR.file'), "00e46d5084204a794818df06df45e7cc4489fd7ada4762c958b3c19c86409193", 'sha256 (hex/file/2)');
is( sha256_file_b64('t/data/text-CR.file'), "AORtUIQgSnlIGN8G30XnzESJ/XraR2LJWLPBnIZAkZM=", 'sha256 (base64/file/2)');
is( digest_file('SHA256', 't/data/text-CR.file'), pack("H*","00e46d5084204a794818df06df45e7cc4489fd7ada4762c958b3c19c86409193"), 'sha256 (digest_file_raw/file/2)');
is( digest_file_hex('SHA256', 't/data/text-CR.file'), "00e46d5084204a794818df06df45e7cc4489fd7ada4762c958b3c19c86409193", 'sha256 (digest_file_hex/file/2)');
is( digest_file_b64('SHA256', 't/data/text-CR.file'), "AORtUIQgSnlIGN8G30XnzESJ/XraR2LJWLPBnIZAkZM=", 'sha256 (digest_file_b64/file/2)');
is( digest_file_b64u('SHA256', 't/data/text-CR.file'), "AORtUIQgSnlIGN8G30XnzESJ_XraR2LJWLPBnIZAkZM", 'sha256 (digest_file_b64u/file/2)');
is( Crypt::Digest::SHA256->new->addfile('t/data/text-CR.file')->hexdigest, "00e46d5084204a794818df06df45e7cc4489fd7ada4762c958b3c19c86409193", 'sha256 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::SHA256->new->addfile($fh)->hexdigest, "00e46d5084204a794818df06df45e7cc4489fd7ada4762c958b3c19c86409193", 'sha256 (OO/filehandle/2)');
  close($fh);
}

is( sha256_file('t/data/text-CRLF.file'), pack("H*","2c28030d9bd766d6ae023e34b3aa84245993f98436cd36db0f0ab2294ffe7b6f"), 'sha256 (raw/file/3)');
is( sha256_file_hex('t/data/text-CRLF.file'), "2c28030d9bd766d6ae023e34b3aa84245993f98436cd36db0f0ab2294ffe7b6f", 'sha256 (hex/file/3)');
is( sha256_file_b64('t/data/text-CRLF.file'), "LCgDDZvXZtauAj40s6qEJFmT+YQ2zTbbDwqyKU/+e28=", 'sha256 (base64/file/3)');
is( digest_file('SHA256', 't/data/text-CRLF.file'), pack("H*","2c28030d9bd766d6ae023e34b3aa84245993f98436cd36db0f0ab2294ffe7b6f"), 'sha256 (digest_file_raw/file/3)');
is( digest_file_hex('SHA256', 't/data/text-CRLF.file'), "2c28030d9bd766d6ae023e34b3aa84245993f98436cd36db0f0ab2294ffe7b6f", 'sha256 (digest_file_hex/file/3)');
is( digest_file_b64('SHA256', 't/data/text-CRLF.file'), "LCgDDZvXZtauAj40s6qEJFmT+YQ2zTbbDwqyKU/+e28=", 'sha256 (digest_file_b64/file/3)');
is( digest_file_b64u('SHA256', 't/data/text-CRLF.file'), "LCgDDZvXZtauAj40s6qEJFmT-YQ2zTbbDwqyKU_-e28", 'sha256 (digest_file_b64u/file/3)');
is( Crypt::Digest::SHA256->new->addfile('t/data/text-CRLF.file')->hexdigest, "2c28030d9bd766d6ae023e34b3aa84245993f98436cd36db0f0ab2294ffe7b6f", 'sha256 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::SHA256->new->addfile($fh)->hexdigest, "2c28030d9bd766d6ae023e34b3aa84245993f98436cd36db0f0ab2294ffe7b6f", 'sha256 (OO/filehandle/3)');
  close($fh);
}

is( sha256_file('t/data/text-LF.file'), pack("H*","f8282483e6c484c95d26581056a406650c94b4cc7649e05beb0660aa578f345b"), 'sha256 (raw/file/4)');
is( sha256_file_hex('t/data/text-LF.file'), "f8282483e6c484c95d26581056a406650c94b4cc7649e05beb0660aa578f345b", 'sha256 (hex/file/4)');
is( sha256_file_b64('t/data/text-LF.file'), "+Cgkg+bEhMldJlgQVqQGZQyUtMx2SeBb6wZgqlePNFs=", 'sha256 (base64/file/4)');
is( digest_file('SHA256', 't/data/text-LF.file'), pack("H*","f8282483e6c484c95d26581056a406650c94b4cc7649e05beb0660aa578f345b"), 'sha256 (digest_file_raw/file/4)');
is( digest_file_hex('SHA256', 't/data/text-LF.file'), "f8282483e6c484c95d26581056a406650c94b4cc7649e05beb0660aa578f345b", 'sha256 (digest_file_hex/file/4)');
is( digest_file_b64('SHA256', 't/data/text-LF.file'), "+Cgkg+bEhMldJlgQVqQGZQyUtMx2SeBb6wZgqlePNFs=", 'sha256 (digest_file_b64/file/4)');
is( digest_file_b64u('SHA256', 't/data/text-LF.file'), "-Cgkg-bEhMldJlgQVqQGZQyUtMx2SeBb6wZgqlePNFs", 'sha256 (digest_file_b64u/file/4)');
is( Crypt::Digest::SHA256->new->addfile('t/data/text-LF.file')->hexdigest, "f8282483e6c484c95d26581056a406650c94b4cc7649e05beb0660aa578f345b", 'sha256 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::SHA256->new->addfile($fh)->hexdigest, "f8282483e6c484c95d26581056a406650c94b4cc7649e05beb0660aa578f345b", 'sha256 (OO/filehandle/4)');
  close($fh);
}
