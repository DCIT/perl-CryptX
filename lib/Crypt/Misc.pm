package Crypt::Misc;

use strict;
use warnings;

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
use Carp 'croak';
our %EXPORT_TAGS = ( all => [qw(encode_b64 decode_b64 encode_b64u decode_b64u pem_to_der der_to_pem read_rawfile write_rawfile slow_eq)] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw(); 

use Carp 'carp';
use CryptX;
use Crypt::Digest 'digest_data';
use Crypt::Mode::CBC;
use Crypt::Mode::CFB;
use Crypt::Mode::ECB;
use Crypt::Mode::OFB;
use Crypt::Cipher;
use Crypt::PRNG 'random_bytes';

sub encode_b64 {
  CryptX::_encode_base64(@_);
}

sub decode_b64  {
  CryptX::_decode_base64(@_);
}

sub encode_b64u {
  CryptX::_encode_base64url(@_);
}

sub decode_b64u {
  CryptX::_decode_base64url(@_);
}

sub pem_to_der {
  my ($data, $password) = @_;

  my ($begin, $obj1, $content, $end, $obj2) = $data =~ m/(----[- ]BEGIN ([^\r\n\-]+KEY)[ -]----)(.*?)(----[- ]END ([^\r\n\-]+)[ -]----)/s;
  return undef unless $content;

  $content =~ s/^\s+//sg;
  $content =~ s/\s+$//sg;
  $content =~ s/\r\n/\n/sg;  # CR-LF >> LF
  $content =~ s/\r/\n/sg;    # CR >> LF
  $content =~ s/\\\n//sg;    # \ + LF

  my ($headers, undef, $b64) = $content =~ /^(([^:]+:.*?\n)*)(.*)$/s;
  return undef unless $b64;

  my $binary = decode_b64($b64);
  return undef unless $binary;

  my ($ptype, $cipher_name, $iv_hex);
  for my $h (split /\n/, ($headers||'')) {
    my ($k, $v) = split /:\s*/, $h, 2;
    $ptype = $v if $k eq 'Proc-Type';
    ($cipher_name, $iv_hex) = $v =~ /^\s*(.*?)\s*,\s*([0-9a-fA-F]+)\s*$/ if $k eq 'DEK-Info';
  }
  if ($cipher_name && $iv_hex && $ptype && $ptype eq '4,ENCRYPTED') {
    croak "FATAL: encrypted PEM but no password provided" unless defined $password;
    my $iv = pack("H*", $iv_hex);
    my ($mode, $klen) = _name2mode($cipher_name);
    my $key = _password2key($password, $klen, $iv, 'MD5');
    return $mode->decrypt($binary, $key, $iv);
  }
  return $binary;
}

sub der_to_pem {
  my ($data, $header_name, $password, $cipher_name) = @_;
  my $content = $data;
  my @headers;

  if ($password) {
    $cipher_name ||= 'AES-256-CBC';
    my ($mode, $klen, $ilen) = _name2mode($cipher_name);
    my $iv = random_bytes($ilen);
    my $key = _password2key($password, $klen, $iv, 'MD5');
    $content = $mode->encrypt($data, $key, $iv);
    push @headers, 'Proc-Type: 4,ENCRYPTED', "DEK-Info: ".uc($cipher_name).",".unpack("H*", $iv);
  }

  my $pem = "-----BEGIN $header_name-----\n";
  if (@headers) {
    $pem .= "$_\n" for @headers;
    $pem .= "\n";
  }
  my @l = encode_b64($content) =~ /.{1,64}/g;
  $pem .= join("\n", @l) . "\n";
  $pem .= "-----END $header_name-----\n";
  return $pem;
}

sub read_rawfile {
  my $f = shift;
  croak "FATAL: read_rawfile() non-existing file '$f'" unless -f $f;
  open my $fh, "<", $f or croak "FATAL: read_rawfile() cannot open file '$f': $!";
  binmode $fh;
  return do { local $/; <$fh> };
}

sub write_rawfile {
  # write_rawfile($filename, $data);
  croak "FATAL: write_rawfile() no data" unless defined $_[1];
  open my $fh, ">", $_[0] or croak "FATAL: write_rawfile() cannot open file '$_[0]': $!";
  binmode $fh;
  print $fh $_[1] or croak "FATAL: write_rawfile() cannot write to '$_[0]': $!";
  close $fh       or croak "FATAL: write_rawfile() cannot close '$_[0]': $!";
  return;
}

sub slow_eq {
  my ($a, $b) = @_;
  return unless defined $a && defined $b;
  my $diff = length $a ^ length $b;
  for(my $i = 0; $i < length $a && $i < length $b; $i++) {
    $diff |= ord(substr $a, $i) ^ ord(substr $b, $i);
  }
  return $diff == 0;
}

###  private functions

sub _name2mode {
  my $cipher_name = uc(shift);
  my %trans = ( 'DES-EDE3' => 'DES_EDE' );

  my ($cipher, undef, $klen, $mode) = $cipher_name =~ /^(AES|CAMELLIA|DES|DES-EDE3|SEED)(-(\d+))?-(CBC|CFB|ECB|OFB)$/i;
  croak "FATAL: unsupported cipher '$cipher_name'" unless $cipher && $mode;
  $cipher = $trans{$cipher} || $cipher;
  $klen = $klen ? int($klen/8) : Crypt::Cipher::min_keysize($cipher);
  my $ilen = Crypt::Cipher::blocksize($cipher);
  croak "FATAL: unsupported cipher '$cipher_name'" unless $klen && $ilen;

  return (Crypt::Mode::CBC->new($cipher), $klen, $ilen) if $mode eq 'CBC';
  return (Crypt::Mode::CFB->new($cipher), $klen, $ilen) if $mode eq 'CFB';
  return (Crypt::Mode::ECB->new($cipher), $klen, $ilen) if $mode eq 'ECB';
  return (Crypt::Mode::OFB->new($cipher), $klen, $ilen) if $mode eq 'OFB';
}

sub _password2key {
  my ($password, $klen, $iv, $hash) = @_;
  my $salt = substr($iv, 0, 8);
  my $key = '';
  while (length($key) < $klen) {
    $key .= digest_data($hash, $key . $password . $salt);
  }
  return substr($key, 0, $klen);
}

1;

=pod

=head1 NAME

Crypt::Misc - miscellaneous functions related to (or used by) CryptX

=head1 SYNOPSIS

 use Crypt::Misc ':all';


=head1 DESCRIPTION

xxx

=head1 METHODS

=head2 encode_b64

xxx

=head2 decode_b64

xxx

=head2  read_rawfile

xxx

=head2  write_rawfile

xxx

=head2  slow_eq

xxx

=head2  encode_b64u

xxx

=head2  decode_b64u

xxx

=head2  pem_to_der

xxx

=head2  der_to_pem

xxx

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>

=back

=cut

__END__
