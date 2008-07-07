#!/usr/bin/perl

use strict;
use warnings;

use iTunes::Sid;

my $sid = iTunes::Sid->new( 
    key            => 'FIND',
    regdata       => '/media/disk-1/regdata',
);

$sid->fetch_all_user_keys();
$sid->write_all_user_keys_to_drms_dir();
