#!/usr/bin/perl 

=head1 NAME

Repo Compare

=head1 ABSTRACT

This script loads an irr-trie and an rpki-trie and compares the entries present in both to check cross-coverage. 

=head1 SYNOPSIS

  ./luke_dbwalker.pl [OPTIONS]

  OPTIONS:
    i    - /path/to/Irr/files     [ ../db/irr/  ]
    p    - /path/to/rPki/files    [ ../db/rpki/ ]
    o    - /path/to/Output/dir    [ ../stash/   ]
    b    - 
            Process IRR-dB-files  [ true ]
    r    - 
            Process RPKI-files    [ true ]
    d    -  
            debug. Gets _really_ chatty.
   

=cut

use strict;
use warnings;
use Getopt::Std;
use Storable;
use Net::Patricia;
use Term::ANSIColor;
use Data::Dumper;
use Local::addrinfo qw( by_cidr mk_iprange_lite mk_iprange is_subset);
use 5.10.0;

my %opts;
getopts( 'i:o:d:b:r', \%opts ) or usage();

our $VERSION = "1.0";

my $input_dir = $opts{i} || '../stash/';


my $pt_rpki_v4 = new Net::Patricia;
my $pt_rpki_v6 = new Net::Patricia AF_INET6;
my $pt_irr_v4 = new Net::Patricia;
my $pt_irr_v6 = new Net::Patricia AF_INET6;

logger("Retrieving Patricia Tries...");

$pt_rpki_v4 = retrieve("../stash/rpki-patricia-v4.storable");
$pt_rpki_v6 = retrieve("../stash/rpki-patricia-v6.storable");
$pt_irr_v4  = retrieve("../stash/irr-patricia-v4.storable");
$pt_irr_v6  = retrieve("../stash/irr-patricia-v4.storable");

logger("Done.");

# Which values from the RPKI Trie are present in the IRRs?
my $rpki_covered_in_irr = 0;
my $rpki_not_found_in_irr = 0;
my $rpki_invalid_in_irr = 0;
my $rpki_count = 0;

# Which values from the IRR Trie are present in the RPKI-Tries??
my $irr_covered_in_rpki = 0;
my $irr_not_found_in_rpki = 0;
my $irr_invalid_in_rpki = 0;

logger("Walking rpkiv4 trie and comparing with irrv4");

$pt_rpki_v4->climb(
  sub {
    $DB::single = 1;
    compare_rpki_with_irr($_[0], $pt_irr_v4);
  }
);


say "Of a total of $rpki_count ROAs, $rpki_covered_in_irr \t\t covered in IRR\n $rpki_not_found_in_irr \t\t not found in IRR \n $rpki_invalid_in_irr\t\t have invalid irr coverage";

sub compare_rpki_with_irr {
  my $node = shift;             # The node returned by the tree climbing
  my $compare_database = shift; # The database to comare against.

  $rpki_count++;
  $DB::single = 1;
  my $result = $compare_database->match_string($node->{prefix});

  my @origin_as_rpki = keys %{ $node->{origin} }; # Holds all possible origin_as from rpki
  my @origin_as_irr  = keys %{ $result->{origin} }; # Holds all possible origin_as from IRR

  my $prefix_length_irr = (split /\//, $result)[1];
  
  # Result holds IRR-Stash  # Result holds IRR-Stash hash
  if ( $result ) { #We found some correspondence
    
    foreach ( keys %{ $node->{origin} }) {
      if ( $result->{origin}->{$_} && $node->{origin}->{$_}->{max_length} > $prefix_length_irr) { 
        $rpki_covered_in_irr++;
        return;
      }
      $rpki_invalid_in_irr++;
    }
  } else {
    $rpki_not_found_in_irr++;
  }
}

































sub logger {
  my $msg = shift;
  my $color = shift || 'reset';
  my $time = get_formated_time();
  print "$time";
  print color('reset');
  print color($color);
  say "$msg";
  print color('reset');
}

sub logger_no_newline {
  my $msg = shift;
  my $color = shift || 'reset';
  my $time = get_formated_time();
  print "$time";
  print color('reset');
  print color($color);
  print "$msg                                  \r";
  STDOUT->flush();
  print color('reset');
}

sub get_formated_time {
  my ($sec, $min, $h) = localtime(time);
  my $time = sprintf '%02d:%02d:%02d : ', $h, $min, $sec;
}
