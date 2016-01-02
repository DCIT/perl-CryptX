package Crypt::PK;

use strict;
use warnings;

use Carp;
use CryptX qw( _encode_base64 _decode_base64 );
use Crypt::Digest qw(digest_data);
use Crypt::Mode::CBC;
use Crypt::Mode::CFB;
use Crypt::Mode::ECB;
use Crypt::Mode::OFB;
use Crypt::Cipher;
use Crypt::PRNG 'random_bytes';

sub _slurp_file {
  my $f = shift;
  croak "FATAL: non-existing file '$f'" unless -f $f;
  local $/ = undef;
  open my $fh, "<", $f or croak "FATAL: couldn't open file: $!";
  binmode $fh;
  my $string = readline($fh);
  close $fh;
  return $string;
}

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

sub _pem_to_binary {
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
  my $binary = _decode_base64($b64);
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

sub _asn1_to_pem {
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

  my $rv = "-----BEGIN $header_name-----\n";
  if (@headers) {
    $rv .= "$_\n" for @headers;
    $rv .= "\n";
  }
  my @l = _encode_base64($content) =~ /.{1,64}/g;
  $rv .= join("\n", @l) . "\n";
  $rv .= "-----END $header_name-----\n";
}

sub _ssh_parse {
  my $raw = shift;
  return unless defined $raw;
  my $len = length($raw);
  my @parts = ();
  my $i = 0;
  while (1) {
    last unless $i + 4 <= $len;
    my $part_len = unpack("N4", substr($raw, $i, 4));
    last unless $i + 4 + $part_len <= $len;
    push @parts, substr($raw, $i + 4, $part_len);
    $i += $part_len + 4;
  }
  return @parts;
}

1;

__END__

=head1 NAME

Crypt::PK - [internal only]

=cut