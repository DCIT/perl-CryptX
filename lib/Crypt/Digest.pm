package Crypt::Digest;

use strict;
use warnings;
our $VERSION = '0.088_002';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

### the following methods/functions are implemented in XS:
# - new
# - hashsize
# - clone
# - reset
# - digest
# - hexdigest
# - b64digest
# - add
# - digest_data
# - digest_data_hex
# - digest_data_b64
# - digest_data_b64u
# - DESTROY

### METHODS

sub addfile {
  my ($self, $file) = @_;

  my ($handle, $close_handle);
  if (ref($file) && eval { defined fileno($file) }) {
    $handle = $file;
  }
  elsif (defined($file) && !ref($file)) {
    open($handle, "<", $file) || croak "FATAL: cannot open '$file': $!";
    binmode($handle);
    $close_handle = 1;
  }
  else {
    croak "FATAL: invalid handle";
  }

  my $n;
  my $buf = "";
  {
    local $SIG{__DIE__} = \&CryptX::_croak;
    while (($n = read($handle, $buf, 32*1024))) {
      $self->add($buf)
    }
    croak "FATAL: read failed: $!" unless defined $n;
  }
  close($handle) if $close_handle;

  return $self;
}

sub CLONE_SKIP { 1 } # prevent cloning

### FUNCTIONS

sub digest_file        { local $SIG{__DIE__} = \&CryptX::_croak; Crypt::Digest->new(shift)->addfile(@_)->digest     }
sub digest_file_hex    { local $SIG{__DIE__} = \&CryptX::_croak; Crypt::Digest->new(shift)->addfile(@_)->hexdigest  }
sub digest_file_b64    { local $SIG{__DIE__} = \&CryptX::_croak; Crypt::Digest->new(shift)->addfile(@_)->b64digest  }
sub digest_file_b64u   { local $SIG{__DIE__} = \&CryptX::_croak; Crypt::Digest->new(shift)->addfile(@_)->b64udigest }

1;

=pod

=head1 NAME

Crypt::Digest - Generic interface to hash/digest functions

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u
                         digest_file digest_file_hex digest_file_b64 digest_file_b64u );

   my $data = 'data string';
   my $filename = 'filename.dat';
   open my $filehandle, '<:raw', $filename or die "cannot open $filename: $!";

   # calculate digest from string/buffer
   my $digest_raw  = digest_data('SHA256', $data);
   my $digest_hex  = digest_data_hex('SHA256', $data);
   my $digest_b64  = digest_data_b64('SHA256', $data);
   my $digest_b64u = digest_data_b64u('SHA256', $data);
   # calculate digest from file
   my $file_digest_raw  = digest_file('SHA256', $filename);
   my $file_digest_hex  = digest_file_hex('SHA256', $filename);
   my $file_digest_b64  = digest_file_b64('SHA256', $filename);
   my $file_digest_b64u = digest_file_b64u('SHA256', $filename);
   # calculate digest from filehandle
   my $fh_digest_raw  = digest_file('SHA256', $filehandle);

   ### OO interface:
   use Crypt::Digest;

   my $d = Crypt::Digest->new('SHA1');
   $d->add('any data');
   $d->addfile('filename.dat');
   $d->addfile($filehandle);
   my $result_raw  = $d->digest;     # raw bytes
   my $result_hex  = $d->hexdigest;  # hexadecimal form
   my $result_b64  = $d->b64digest;  # Base64 form
   my $result_b64u = $d->b64udigest; # Base64 URL Safe form

=head1 DESCRIPTION

Provides an interface to various hash/digest algorithms.

All functions and methods return raw bytes unless the method name explicitly
ends in C<_hex>, C<_b64>, or C<_b64u>. Invalid algorithm names croak.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u
                        digest_file digest_file_hex digest_file_b64 digest_file_b64u );

Or all of them at once:

  use Crypt::Digest ':all';

=head1 FUNCTIONS

Please note that all functions take as its first argument the algorithm name, supported values are:

 'CHAES', 'MD2', 'MD4', 'MD5', 'RIPEMD128', 'RIPEMD160',
 'RIPEMD256', 'RIPEMD320', 'SHA1', 'SHA224', 'SHA256',
 'SHA384', 'SHA512', 'SHA512_224', 'SHA512_256', 'Tiger192', 'Whirlpool',
 'SHA3_224', 'SHA3_256', 'SHA3_384', 'SHA3_512',
 'Keccak224', 'Keccak256', 'Keccak384', 'Keccak512',
 'BLAKE2b_160', 'BLAKE2b_256', 'BLAKE2b_384', 'BLAKE2b_512',
 'BLAKE2s_128', 'BLAKE2s_160', 'BLAKE2s_224', 'BLAKE2s_256'

 (simply any <NAME> for which there is Crypt::Digest::<NAME> module)

=head2 digest_data

Logically joins all arguments into a single string, and returns the digest for
the selected algorithm encoded as a binary string.

Data arguments are converted to byte strings using Perl's usual scalar
stringification. Defined scalars, including numbers and string-overloaded
objects, are accepted. C<undef> is treated as an empty string and may emit
Perl's usual "uninitialized value" warning. The same rules apply to
C<digest_data_hex>, C<digest_data_b64>, and C<digest_data_b64u>.

 my $digest_raw = digest_data('SHA256', 'data string');
 #or
 my $digest_raw = digest_data('SHA256', 'any data', 'more data', 'even more data');

=head2 digest_data_hex

Logically joins all arguments into a single string, and returns the digest for
the selected algorithm encoded as a hexadecimal string.

 my $digest_hex = digest_data_hex('SHA256', 'data string');
 #or
 my $digest_hex = digest_data_hex('SHA256', 'any data', 'more data', 'even more data');

=head2 digest_data_b64

Logically joins all arguments into a single string, and returns the digest for
the selected algorithm encoded as a Base64 string, B<with> trailing '=' padding.

 my $digest_b64 = digest_data_b64('SHA256', 'data string');
 #or
 my $digest_b64 = digest_data_b64('SHA256', 'any data', 'more data', 'even more data');

=head2 digest_data_b64u

Logically joins all arguments into a single string, and returns the digest for
the selected algorithm encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $digest_b64url = digest_data_b64u('SHA256', 'data string');
 #or
 my $digest_b64url = digest_data_b64u('SHA256', 'any data', 'more data', 'even more data');

=head2 digest_file

Reads file (defined by filename or filehandle) content, and returns its digest encoded as a binary string.

 my $digest_raw = digest_file('SHA256', 'filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $digest_raw = digest_file('SHA256', $filehandle);

=head2 digest_file_hex

Reads file (defined by filename or filehandle) content, and returns its digest encoded as a hexadecimal string.

 my $digest_hex = digest_file_hex('SHA256', 'filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $digest_hex = digest_file_hex('SHA256', $filehandle);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 digest_file_b64

Reads file (defined by filename or filehandle) content, and returns its digest encoded as a Base64 string, B<with> trailing '=' padding.

 my $digest_b64 = digest_file_b64('SHA256', 'filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $digest_b64 = digest_file_b64('SHA256', $filehandle);

=head2 digest_file_b64u

Reads file (defined by filename or filehandle) content, and returns its digest encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $digest_b64url = digest_file_b64u('SHA256', 'filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $digest_b64url = digest_file_b64u('SHA256', $filehandle);

=head1 METHODS

Unless noted otherwise, assume C<$d> is an existing digest object created via
C<new>, for example:

 my $d = Crypt::Digest->new('SHA256');

=head2 new

Constructor, returns a reference to the digest object.

 my $d = Crypt::Digest->new($name);
 # $name could be: 'CHAES', 'MD2', 'MD4', 'MD5', 'RIPEMD128', 'RIPEMD160',
 #                 'RIPEMD256', 'RIPEMD320', 'SHA1', 'SHA224', 'SHA256', 'SHA384',
 #                 'SHA512', 'SHA512_224', 'SHA512_256', 'SHA3_224', 'SHA3_256',
 #                 'SHA3_384', 'SHA3_512', 'Keccak224', 'Keccak256', 'Keccak384',
 #                 'Keccak512', 'BLAKE2b_160', 'BLAKE2b_256', 'BLAKE2b_384',
 #                 'BLAKE2b_512', 'BLAKE2s_128', 'BLAKE2s_160', 'BLAKE2s_224',
 #                 'BLAKE2s_256', 'Tiger192', 'Whirlpool'
 #
 # simply any <FUNCNAME> for which there is Crypt::Digest::<FUNCNAME> module

=head2 clone

Creates a copy of the digest object state and returns a reference to the copy.

 $d->clone();

=head2 reset

Reinitialize the digest object state and returns a reference to the digest object.

 $d->reset();

=head2 add

All arguments are appended to the message we calculate digest for.
The return value is the digest object itself.

Each argument is converted to bytes using Perl's usual scalar stringification.
Defined scalars, including numbers and string-overloaded objects, are
accepted. C<undef> is treated as an empty string and may emit Perl's usual
"uninitialized value" warning.

 $d->add('any data');
 #or
 $d->add('any data', 'more data', 'even more data');

Note that all the following cases are equivalent:

 # case 1
 $d->add('aa', 'bb', 'cc');

 # case 2
 $d->add('aa');
 $d->add('bb');
 $d->add('cc');

 # case 3
 $d->add('aabbcc');

 # case 4
 $d->add('aa')->add('bb')->add('cc');

=head2 addfile

The content of the file (or filehandle) is appended to the message we calculate digest for.
The return value is the digest object itself.

 $d->addfile('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 $d->addfile($filehandle);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 hashsize

Returns the length of calculated digest in bytes (e.g. 32 for SHA-256).

 $d->hashsize;
 #or
 Crypt::Digest->hashsize('SHA1');
 #or
 Crypt::Digest::hashsize('SHA1');

=head2 digest

Returns the binary digest (raw bytes).
The first call finalizes the digest object. Any later C<add()>,
C<addfile()>, C<digest()>, C<hexdigest()>, C<b64digest()>, or
C<b64udigest()> call will fail until you call C<reset()>.

 my $result_raw = $d->digest();

=head2 hexdigest

Returns the digest encoded as a hexadecimal string.
Like C<digest()>, the first call finalizes the digest object.

 my $result_hex = $d->hexdigest();

=head2 b64digest

Returns the digest encoded as a Base64 string, B<with> trailing '=' padding (B<BEWARE:> this padding
style might differ from other Digest::<SOMETHING> modules on CPAN).
Like C<digest()>, the first call finalizes the digest object.

 my $result_b64 = $d->b64digest();

=head2 b64udigest

Returns the digest encoded as a Base64 URL Safe string (see RFC 4648 section 5).
Like C<digest()>, the first call finalizes the digest object.

 my $result_b64url = $d->b64udigest();

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>

=item * L<Crypt::Digest|Crypt::Digest> tries to be compatible with L<Digest|Digest> interface.

=item * Check subclasses like L<Crypt::Digest::SHA1|Crypt::Digest::SHA1>, L<Crypt::Digest::MD5|Crypt::Digest::MD5>, ...

=back

=cut
