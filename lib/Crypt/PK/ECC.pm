package Crypt::PK::ECC;

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( ecc_encrypt ecc_decrypt ecc_sign ecc_verify ecc_shared_secret )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;
use Crypt::Digest;
use Carp;
use MIME::Base64 qw(encode_base64 decode_base64);

sub new { 
  my ($class, $f) = @_;
  my $self = _new();
  $self->import_key($f) if $f;
  return  $self;
}

sub export_key_pem {
  my ($self, $type) = @_;
  my $key = $self->export_key_der($type||'');
  return undef unless $key;
  
  return "-----BEGIN EC PRIVATE KEY-----\n" .
         encode_base64($key) .
         "-----END EC PRIVATE KEY-----\n " if $type eq 'private';
  
  return "-----BEGIN PUBLIC KEY-----\n" .
         encode_base64($key) .
         "-----END PUBLIC KEY-----\n " if $type eq 'public';
}

sub import_key {
  my ($self, $data) = @_;
  croak "FATAL: undefined key" unless $data;
  $data = _slurp_file($data) if -f $data;
  if ($data =~ /-----BEGIN (EC PRIVATE|EC PUBLIC|PRIVATE|PUBLIC) KEY-----(.*?)-----END/sg) {
    $data = decode_base64($2);
  }
  croak "FATAL: invalid key format" unless $data;
  $self->_import($data);
  return $self;
}

sub encrypt {
  my ($self, $data, $hash_name) = @_;
  $hash_name = Crypt::Digest::_trans_digest_name($hash_name||'SHA1');  
  return $self->_encrypt($data, $hash_name);
}

sub decrypt {
  my ($self, $data) = @_; 
  return $self->_decrypt($data);
}

sub sign {
  my ($self, $data) = @_;  
  return $self->_sign($data);
}

sub verify {
  my ($self, $sig, $data) = @_;  
  return $self->_verify($sig, $data);
}

### FUNCTIONS

sub ecc_encrypt {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->encrypt(@_);
}

sub ecc_decrypt {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;  
  return $key->decrypt(@_);
}

sub ecc_sign {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;  
  return $key->sign(@_);
}

sub ecc_verify {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__; 
  return $key->verify(@_);
}

sub ecc_shared_secret {
  my ($privkey, $pubkey) = @_;
  $privkey = __PACKAGE__->new($privkey) unless ref $privkey;
  $pubkey  = __PACKAGE__->new($pubkey)  unless ref $pubkey;
  carp "FATAL: invalid 'privkey' param" unless ref($privkey) eq __PACKAGE__ && $privkey->is_private;
  carp "FATAL: invalid 'pubkey' param"  unless ref($pubkey)  eq __PACKAGE__;
  return $privkey->shared_secret($pubkey);
}

sub _slurp_file {
  my $f = shift;
  local $/ = undef;
  open FILE, "<", $f or croak "FATAL: couldn't open file: $!";
  binmode FILE;
  my $string = <FILE>;
  close FILE;
  return $string;
}

1;

=pod

=head1 NAME

__PACKAGE__ - XXX-TODO

=head1 FUNCTIONS

=head2 ecc_encrypt

=head2 ecc_decrypt

=head2 ecc_sign

=head2 ecc_verify

=head2 ecc_shared_secret

=head1 METHODS

=head2 new

=head2 generate_key

=head2 import_key

=head2 import_key_x963

=head2 export_key_pem

=head2 export_key_der

=head2 export_key_x963

=head2 encrypt

=head2 decrypt

=head2 sign

=head2 verify

=head2 shared_secret

=head2 is_private

=head2 size

