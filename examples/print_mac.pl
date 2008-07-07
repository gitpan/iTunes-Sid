#!/usr/bin/perl

use strict;
use warnings;

use iTunes::Sid;

my $sid = iTunes::Sid->new(  
    key => 'FIND',
    IV  => 'FIND',
}

print "mac=", $sid->mac;

