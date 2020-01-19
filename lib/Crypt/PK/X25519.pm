package Crypt::PK::X25519;

use strict;
use warnings;
our $VERSION = '0.066_001';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;
use Crypt::PK;
use Crypt::Misc qw(read_rawfile encode_b64u decode_b64u encode_b64 decode_b64 pem_to_der der_to_pem);

sub new {
  my $self = shift->_new();
  return @_ > 0 ? $self->import_key(@_) : $self;
}

sub import_key_raw {
  my ($self, $key, $type) = @_;
  croak "FATAL: undefined key" unless $key;
  croak "FATAL: undefined type" unless $type;
  return $self->_import_raw($key, 1) if $type eq 'private';
  return $self->_import_raw($key, 0) if $type eq 'public';
  croak "FATAL: invalid key type '$type'";
}

sub import_key {
  my ($self, $key, $password) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  croak "FATAL: undefined key" unless $key;

  # special case
  if (ref($key) eq 'HASH') {
    if ($key->{kty} && $key->{kty} eq "OKP" && $key->{crv} && $key->{crv} eq 'X25519') {
      # JWK-like structure e.g.
      # {"kty":"OKP","crv":"X25519","d":"...","x":"..."}
      return $self->_import_raw(decode_b64u($key->{d}), 1) if $key->{d}; # private
      return $self->_import_raw(decode_b64u($key->{x}), 0) if $key->{x}; # public
    }
    if ($key->{curve} && $key->{curve} eq "x25519" && ($key->{priv} || $key->{pub})) {
      # hash exported via key2hash
      return $self->_import_raw(pack("H*", $key->{priv}), 1) if $key->{priv};
      return $self->_import_raw(pack("H*", $key->{pub}),  0) if $key->{pub};
    }
    croak "FATAL: unexpected X25519 key hash";
  }

  my $data;
  if (ref($key) eq 'SCALAR') {
    $data = $$key;
  }
  elsif (-f $key) {
    $data = read_rawfile($key);
  }
  else {
    croak "FATAL: non-existing file '$key'";
  }
  croak "FATAL: invalid key data" unless $data;

  if ($data =~ /-----BEGIN PUBLIC KEY-----(.*?)-----END/sg) {
    $data = pem_to_der($data, $password);
    return $self->_import($data);
  }
  elsif ($data =~ /-----BEGIN PRIVATE KEY-----(.*?)-----END/sg) {
    $data = pem_to_der($data, $password);
    return $self->_import_pkcs8($data, $password);
  }
  elsif ($data =~ /-----BEGIN ENCRYPTED PRIVATE KEY-----(.*?)-----END/sg) {
    $data = pem_to_der($data, $password);
    return $self->_import_pkcs8($data, $password);
  }
  elsif ($data =~ /-----BEGIN X25519 PRIVATE KEY-----(.*?)-----END/sg) {
    $data = pem_to_der($data, $password);
    return $self->_import_pkcs8($data, $password);
  }
  elsif ($data =~ /^\s*(\{.*?\})\s*$/s) { # JSON
    my $h = CryptX::_decode_json("$1");
    if ($h->{kty} && $h->{kty} eq "OKP" && $h->{crv} && $h->{crv} eq 'X25519') {
      return $self->_import_raw(decode_b64u($h->{d}), 1) if $h->{d}; # private
      return $self->_import_raw(decode_b64u($h->{x}), 0) if $h->{x}; # public
    }
  }
  elsif (length($data) == 32) {
    croak "FATAL: use import_key_raw() to load raw (32 bytes) X25519 key";
  }
  else {
    my $rv = eval { $self->_import($data) }                  ||
             eval { $self->_import_pkcs8($data, $password) } ||
             eval { $self->_import_x509($data) };
    return $rv if $rv;
  }
  croak "FATAL: invalid or unsupported X25519 key format";
}

sub export_key_pem {
  my ($self, $type, $password, $cipher) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  my $key = $self->export_key_der($type||'');
  return unless $key;
  return der_to_pem($key, "X25519 PRIVATE KEY", $password, $cipher) if substr($type, 0, 7) eq 'private';
  return der_to_pem($key, "PUBLIC KEY") if substr($type,0, 6) eq 'public';
}

sub export_key_jwk {
  my ($self, $type, $wanthash) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  my $kh = $self->key2hash;
  return unless $kh;
  my $hash = { kty => "OKP", crv => "X25519" };
  $hash->{x} = encode_b64u(pack("H*", $kh->{pub}));
  $hash->{d} = encode_b64u(pack("H*", $kh->{priv})) if $type && $type eq 'private' && $kh->{priv};
  return $wanthash ? $hash : CryptX::_encode_json($hash);
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::PK::X25519 - Asymmetric cryptography based on X25519

=head1 SYNOPSIS

=head1 METHODS

=head2 new

=head2 generate_key

=head2 import_key

=head2 import_key_raw

=head2 export_key_der

=head2 export_key_pem

=head2 export_key_jwk

=head2 export_key_raw

=head2 shared_secret

=head2 is_private

=head2 key2hash

=cut
