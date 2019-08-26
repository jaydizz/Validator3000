#!/usr/bin/perl 

use strict;
use warnings;

use 5.10.0;
use Net::Patricia;
use Storable;

my $pt4 = new Net::Patricia;

$pt4 = retrieve("../stash/irr-patricia-v4.storable");

$pt4->climb(
  sub {
    if keys %{ $_[0]->{origin} }


