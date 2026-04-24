package Crypt::PK::X448;

use strict;
use warnings;
our $VERSION = '0.088_001';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw( )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;
use Crypt::PK;
use Crypt::Misc qw(read_rawfile encode_b64u decode_b64u der_to_pem);

sub new {
  my $self = shift->_new();
  return @_ > 0 ? $self->import_key(@_) : $self;
}

sub import_key_raw {
  my ($self, $key, $type) = @_;
  croak "FATAL: undefined key" unless $key;
  croak "FATAL: invalid key" unless length($key) == 56;
  croak "FATAL: undefined type" unless $type;
  return $self->_import_raw($key, 1) if $type eq 'private';
  return $self->_import_raw($key, 0) if $type eq 'public';
  croak "FATAL: invalid key type '$type'";
}

sub import_key {
  my ($self, $key, $password) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  croak "FATAL: undefined key" unless $key;

  if (ref($key) eq 'HASH') {
    if ($key->{kty} && $key->{kty} eq "OKP" && $key->{crv} && $key->{crv} eq 'X448') {
      return $self->_import_raw(decode_b64u($key->{d}), 1) if $key->{d};
      return $self->_import_raw(decode_b64u($key->{x}), 0) if $key->{x};
    }
    if ($key->{curve} && $key->{curve} eq "x448" && ($key->{priv} || $key->{pub})) {
      return $self->_import_raw(pack("H*", $key->{priv}), 1) if $key->{priv};
      return $self->_import_raw(pack("H*", $key->{pub}),  0) if $key->{pub};
    }
    croak "FATAL: unexpected X448 key hash";
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

  if ($data =~ /-----BEGIN (PUBLIC|PRIVATE|ENCRYPTED PRIVATE) KEY-----(.+?)-----END (PUBLIC|PRIVATE|ENCRYPTED PRIVATE) KEY-----/s) {
    return $self->_import_pem($data, $password);
  }
  elsif ($data =~ /^\s*(\{.*?\})\s*$/s) {
    my $h = CryptX::_decode_json("$1") || {};
    if ($h->{kty} && $h->{kty} eq "OKP" && $h->{crv} && $h->{crv} eq 'X448') {
      return $self->_import_raw(decode_b64u($h->{d}), 1) if $h->{d};
      return $self->_import_raw(decode_b64u($h->{x}), 0) if $h->{x};
    }
  }
  elsif (length($data) == 56) {
    croak "FATAL: use import_key_raw() to load raw (56 bytes) X448 key";
  }
  else {
    my $rv = eval { $self->_import($data) }                  ||
             eval { $self->_import_pkcs8($data, $password) } ||
             eval { $self->_import_x509($data) };
    return $rv if $rv;
  }
  croak "FATAL: invalid or unsupported X448 key format";
}

sub export_key_pem {
  my ($self, $type, $password, $cipher) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  my $key = $self->export_key_der($type||'');
  return unless $key;
  return der_to_pem($key, "PRIVATE KEY", $password, $cipher) if substr($type, 0, 7) eq 'private';
  return der_to_pem($key, "PUBLIC KEY") if substr($type,0, 6) eq 'public';
}

sub export_key_jwk {
  my ($self, $type, $wanthash) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  my $kh = $self->key2hash;
  return unless $kh;
  my $hash = { kty => "OKP", crv => "X448" };
  $hash->{x} = encode_b64u(pack("H*", $kh->{pub}));
  $hash->{d} = encode_b64u(pack("H*", $kh->{priv})) if $type && $type eq 'private' && $kh->{priv};
  return $wanthash ? $hash : CryptX::_encode_json($hash);
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::PK::X448 - Asymmetric cryptography based on X448

=head1 SYNOPSIS

 use Crypt::PK::X448;

 my $alice = Crypt::PK::X448->new('Alice_priv_x448.der');
 my $bob   = Crypt::PK::X448->new('Bob_pub_x448.der');
 my $shared_secret = $alice->shared_secret($bob);

 my $pk = Crypt::PK::X448->new;
 $pk->import_key_raw(pack("H*", "cf807ab0fc3efa03108469f29e499db2eefefeb12544d8d4e711f187385aaf31b4f38c8f84a3dd9e43da309fd410c3816a50e644b5500c05"), "public");

 my $sk = Crypt::PK::X448->new;
 $sk->import_key_raw(pack("H*", "10d418b111401956abc5a92c2fbb8406d1d646ba930fdefa2108efe68f2000973755aa952be018f640947c05135fbf9925ebd4da828d86ec"), "private");

 my $generated = Crypt::PK::X448->new->generate_key;
 my $private_der = $generated->export_key_der('private');
 my $public_pem  = $generated->export_key_pem('public');
 my $private_jwk = $generated->export_key_jwk('private');

=head1 DESCRIPTION

I<Since: CryptX-0.100>

=head1 METHODS

=head2 new

I<Since: CryptX-0.100>

 my $pk = Crypt::PK::X448->new();
 my $pk = Crypt::PK::X448->new($filename);
 my $pk = Crypt::PK::X448->new(\$buffer);
 my $pk = Crypt::PK::X448->new($filename, $password);

=head2 generate_key

I<Since: CryptX-0.100>

 $pk->generate_key;

=head2 import_key

I<Since: CryptX-0.100>

Loads X448 private or public keys from DER, PEM, PKCS#8, SubjectPublicKeyInfo, or JWK.

 $pk->import_key($filename);
 $pk->import_key(\$buffer);
 $pk->import_key($filename, $password);
 $pk->import_key({
   curve => "x448",
   pub   => "CF807AB0FC3EFA03108469F29E499DB2EEFEFEB12544D8D4E711F187385AAF31B4F38C8F84A3DD9E43DA309FD410C3816A50E644B5500C05",
   priv  => "10D418B111401956ABC5A92C2FBB8406D1D646BA930FDEFA2108EFE68F2000973755AA952BE018F640947C05135FBF9925EBD4DA828D86EC",
 });
 $pk->import_key({
   kty => "OKP",
   crv => "X448",
   d   => "ENQYsRFAGVarxaksL7uEBtHWRrqTD976IQjv5o8gAJc3VaqVK-AY9kCUfAUTX7-ZJevU2oKNhuw",
   x   => "z4B6sPw--gMQhGnynkmdsu7-_rElRNjU5xHxhzharzG084yPhKPdnkPaMJ_UEMOBalDmRLVQDAU",
 });

=head2 import_key_raw

I<Since: CryptX-0.100>

Import raw public/private key bytes.

 $pk->import_key_raw($key, 'public');
 $pk->import_key_raw($key, 'private');

The raw key must be exactly 56 bytes long.

=head2 export_key_der

I<Since: CryptX-0.100>

 my $der = $pk->export_key_der('private');
 my $der = $pk->export_key_der('public');

=head2 export_key_pem

I<Since: CryptX-0.100>

 my $pem = $pk->export_key_pem('private');
 my $pem = $pk->export_key_pem('public');
 my $pem = $pk->export_key_pem('private', $password, 'AES-256-CBC');

=head2 export_key_jwk

I<Since: CryptX-0.100>

 my $json = $pk->export_key_jwk('private');
 my $hash = $pk->export_key_jwk('public', 1);

=head2 export_key_raw

I<Since: CryptX-0.100>

 my $raw = $pk->export_key_raw('private');
 my $raw = $pk->export_key_raw('public');

=head2 shared_secret

I<Since: CryptX-0.100>

 my $shared_secret = $private_key->shared_secret($public_key);

=head2 is_private

I<Since: CryptX-0.100>

 my $rv = $pk->is_private;

=head2 key2hash

I<Since: CryptX-0.100>

 my $hash = $pk->key2hash;

Returns a hash like:

 {
   curve => "x448",
   pub   => "CF807AB0FC3EFA03108469F29E499DB2EEFEFEB12544D8D4E711F187385AAF31B4F38C8F84A3DD9E43DA309FD410C3816A50E644B5500C05",
   priv  => "10D418B111401956ABC5A92C2FBB8406D1D646BA930FDEFA2108EFE68F2000973755AA952BE018F640947C05135FBF9925EBD4DA828D86EC",
 }

=head1 SEE ALSO

=over

=item * L<https://www.rfc-editor.org/rfc/rfc7748>

=item * L<Crypt::PK::X25519>

=back

=cut
