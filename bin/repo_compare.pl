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

use InfluxDB::LineProtocol qw(data2line line2data);
use InfluxDB::HTTP;

use 5.10.0;

my %opts;
getopts( 'i:o:d:b:r', \%opts ) or usage();

our $VERSION = "1.0";

my $input_dir = $opts{i} || '/home/debian/ba/stash/';


my $pt_rpki_v4 = new Net::Patricia;
my $pt_rpki_v6 = new Net::Patricia AF_INET6;
my $pt_irr_v4 = new Net::Patricia;
my $pt_irr_v6 = new Net::Patricia AF_INET6;


#
# Influx Stuff
# Connecting to InfluxDB and testing.
#
my $METRIC = "repo_compare";
my $METRIC_COUNT = "rpki_refix_count";

our $INFLUX = InfluxDB::HTTP->new(
  host => 'localhost',
  port => 8086,
);
logger("Opening Connection to Influx-DB");
logger("Testing...");
my $ping = $INFLUX->ping();
if ($ping) {
  logger( "Influx Version " . $ping->version . "ready for duty!");
} else {
  die "Influx not working. \n";
}

#
# Patricia
#

logger("Retrieving Patricia Tries...");

$pt_rpki_v4 = retrieve("$input_dir/rpki-patricia-v4.storable");
$pt_rpki_v6 = retrieve("$input_dir/rpki-patricia-v6.storable");
$pt_irr_v4  = retrieve("$input_dir/irr-patricia-v4.storable");
$pt_irr_v6  = retrieve("$input_dir/irr-patricia-v6.storable");

logger("Done.");

# Which values from the RPKI Trie are present in the IRRs?
my $rpki_partially_covering = 0;
my $rpki_exactly_covering = 0;
my $rpki_not_found_in_irr = 0;
my $rpki_invalid_in_irr = 0;
my $rpki_count = 0;

# Which values from the IRR Trie are present in the RPKI-Tries??
my $irr_covered_in_rpki = 0;
my $irr_not_found_in_rpki = 0;
my $irr_invalid_in_rpki = 0;

logger("Walking rpkiv4 trie and comparing with irrv4");

####################################
######### Beginning of Main ########
####################################

$pt_rpki_v4->climb(
  sub {
    $DB::single = 1;
    compare_rpki_with_irr($_[0], $pt_irr_v4);
  }
);


my $covered_percent   = 100*$rpki_exactly_covering / $rpki_count;
my $partially_percent   = 100*$rpki_partially_covering / $rpki_count;
my $not_found_percent = 100*$rpki_not_found_in_irr / $rpki_count;
my $invalid_percent   = 100*$rpki_invalid_in_irr / $rpki_count;

my @influx_lines;
push @influx_lines, data2line($METRIC, $covered_percent,   { af => '4', status => 'covered'   }  );
push @influx_lines, data2line($METRIC, $partially_percent, { af => '4', status => 'partially' }  );
push @influx_lines, data2line($METRIC, $not_found_percent, { af => '4', status => 'note_found'}  );
push @influx_lines, data2line($METRIC, $invalid_percent,   { af => '4', status => 'conflict'  }  );
push @influx_lines, data2line($METRIC_COUNT, $rpki_count, { af => '4'} );

my $res = $INFLUX->write(
   \@influx_lines,
   database    => "test_measure"
  );
  say "Error writing dataset\n $res" unless ($res);


printf("Found a total of %i prefixes in ROAs. Compared to IRR:\n %i (%.2f %%) \t\t\t\t are exactly covered by route-objects\n %i (%.2f %%) \t\t\t\thave more ros than rpki-origins \n %i (%.2f %%) \t\t\t\t are not found as route-object\n %i (%.2f %%) \t\t\t\t are conflicting with route-objects\n", $rpki_count, $rpki_exactly_covering, $covered_percent, $rpki_partially_covering, $partially_percent, $rpki_not_found_in_irr, $not_found_percent, $rpki_invalid_in_irr, $invalid_percent);


$rpki_partially_covering = 0;
$rpki_exactly_covering = 0;
$rpki_not_found_in_irr = 0;
$rpki_invalid_in_irr = 0;
$rpki_count = 0;

$pt_rpki_v6->climb(
  sub {
    $DB::single = 1;
    compare_rpki_with_irr($_[0], $pt_irr_v6);
  }
);


$covered_percent   = 100*$rpki_exactly_covering / $rpki_count;
$partially_percent   = 100*$rpki_partially_covering / $rpki_count;
$not_found_percent = 100*$rpki_not_found_in_irr / $rpki_count;
$invalid_percent   = 100*$rpki_invalid_in_irr / $rpki_count;

@influx_lines = ();
push @influx_lines, data2line($METRIC, $covered_percent,   { af => '6', status => 'covered'   }  );
push @influx_lines, data2line($METRIC, $partially_percent, { af => '6', status => 'partially' }  );
push @influx_lines, data2line($METRIC, $not_found_percent, { af => '6', status => 'note_found'}  );
push @influx_lines, data2line($METRIC, $invalid_percent,   { af => '6', status => 'conflict'  }  );
push @influx_lines, data2line($METRIC_COUNT, $rpki_count, {af => '6'}  );

my $res = $INFLUX->write(
   \@influx_lines,
   database    => "test_measure"
  );
  say "Error writing dataset\n $res" unless ($res);


printf("Found a total of %i prefixes in ROAs. Compared to IRR:\n %i (%.2f %%) \t\t\t\t are exactly covered by route-objects\n %i (%.2f %%) \t\t\t\thave more ros than rpki-origins \n %i (%.2f %%) \t\t\t\t are not found as route-object\n %i (%.2f %%) \t\t\t\t are conflicting with route-objects\n", $rpki_count, $rpki_exactly_covering, $covered_percent, $rpki_partially_covering, $partially_percent, $rpki_not_found_in_irr, $not_found_percent, $rpki_invalid_in_irr, $invalid_percent);


####################################
######### END of Main ##############
####################################


sub compare_rpki_with_irr {
  my $node = shift;             # The node returned by the tree climbing
  my $compare_database = shift; # The database to comare against.

  $rpki_count++;
  $DB::single = 1;
  my $result = $compare_database->match_string($node->{prefix});
  my $conflict_flag = 0;

  # Result holds IRR-Stash  # Result holds IRR-Stash hash
  if ( $result ) { #We found some correspondence
    my $matches = 0;
    foreach my $origin_as ( keys %{ $node->{origin} } ) {
      if ( $result->{origin}->{$origin_as} ) {
        $matches++;
      }
      if ( $result->{length} > $node->{origin}->{$origin_as}->{max_length} ) {
        $conflict_flag++;
      }
    }
    if ( $matches == keys %{ $node->{origin} } ) {
      #say Dumper ($node, $result);
      $rpki_exactly_covering++;
      return;
    }
    if ( $matches > 1 ) {
      $rpki_partially_covering++;
      #say Dumper ($node, $result);
    }
    if ( $conflict_flag ) {
      $rpki_invalid_in_irr++;
    }
    #say " ===========Invalid============";
    #say Dumper ($node, $result);
    $rpki_invalid_in_irr++;
    #say " =========== END Invalid============";
  }
  #say " ===========NotFound============";
  #say Dumper ($node, $result);
  #say " =========== END NotFound============";
  $rpki_not_found_in_irr++;
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

