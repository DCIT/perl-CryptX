package Crypt::PRNG::Sober128;

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( random_bytes )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;
use base 'Crypt::PRNG';

1;

=pod

=head1 NAME

Crypt::PRNG - XXX-TODO