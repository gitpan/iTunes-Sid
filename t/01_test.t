# t/01_test.t - check module loading, etc

use strict;
use warnings;

#use Test::More tests => 3;
use Test::More tests => 2;

BEGIN { use_ok('iTunes::Sid'); }


my $object = iTunes::Sid->new;
isa_ok( $object, 'iTunes::Sid' );

#my $sidb = iTunes::Sid->new( 
#  file => 't/sidb', 
#  DEBUG => 2, 
#  DEBUGDUMPFILE => 't/sidb_dump.html',
#);

#isa_ok( $sidb, 'iTunes::Sid' );
