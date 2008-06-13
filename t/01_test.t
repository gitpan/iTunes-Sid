# t/01_test.t - check module loading, etc

use strict;
use warnings;

use Test::More tests => 2;

BEGIN { use_ok('iTunes::Sid'); }


my $object = iTunes::Sid->new;
isa_ok( $object, 'iTunes::Sid' );

