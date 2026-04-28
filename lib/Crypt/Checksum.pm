package Crypt::Checksum;

use strict;
use warnings;
our $VERSION = '0.088_002';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw/ adler32_data adler32_data_hex adler32_data_int adler32_file adler32_file_hex adler32_file_int
                                 crc32_data crc32_data_hex crc32_data_int crc32_file crc32_file_hex crc32_file_int /] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

# obsolete since v0.057, only for backwards compatibility
sub adler32_data        { require Crypt::Checksum::Adler32; goto \&Crypt::Checksum::Adler32::adler32_data     }
sub adler32_data_hex    { require Crypt::Checksum::Adler32; goto \&Crypt::Checksum::Adler32::adler32_data_hex }
sub adler32_data_int    { require Crypt::Checksum::Adler32; goto \&Crypt::Checksum::Adler32::adler32_data_int }
sub adler32_file        { require Crypt::Checksum::Adler32; goto \&Crypt::Checksum::Adler32::adler32_file     }
sub adler32_file_hex    { require Crypt::Checksum::Adler32; goto \&Crypt::Checksum::Adler32::adler32_file_hex }
sub adler32_file_int    { require Crypt::Checksum::Adler32; goto \&Crypt::Checksum::Adler32::adler32_file_int }
sub crc32_data          { require Crypt::Checksum::CRC32;   goto \&Crypt::Checksum::CRC32::crc32_data         }
sub crc32_data_hex      { require Crypt::Checksum::CRC32;   goto \&Crypt::Checksum::CRC32::crc32_data_hex     }
sub crc32_data_int      { require Crypt::Checksum::CRC32;   goto \&Crypt::Checksum::CRC32::crc32_data_int     }
sub crc32_file          { require Crypt::Checksum::CRC32;   goto \&Crypt::Checksum::CRC32::crc32_file         }
sub crc32_file_hex      { require Crypt::Checksum::CRC32;   goto \&Crypt::Checksum::CRC32::crc32_file_hex     }
sub crc32_file_int      { require Crypt::Checksum::CRC32;   goto \&Crypt::Checksum::CRC32::crc32_file_int     }

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
      $self->add($buf);
    }
    croak "FATAL: read failed: $!" unless defined $n;
  }
  close($handle) if $close_handle;

  return $self;
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::Checksum - [internal only]

=head1 SYNOPSIS

Do not use this module directly in new code.

Use L<Crypt::Checksum::CRC32> or L<Crypt::Checksum::Adler32> instead.

=head1 DESCRIPTION

Compatibility wrapper for the checksum modules.

Do not use this module directly in new code. Use
L<Crypt::Checksum::CRC32> or L<Crypt::Checksum::Adler32> instead.

=cut
