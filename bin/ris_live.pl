#!/usr/bin/perl

use warnings;
use strict;

use Term::ANSIColor;

use Mojo::Transaction::WebSocket;
use Mojo::UserAgent;
use Mojo::JSON qw(decode_json encode_json);

use InfluxDB::LineProtocol qw(data2line line2data);
use InfluxDB::HTTP;

use Storable;

use Net::Patricia;

use Time::HiRes qw( usleep ualarm gettimeofday tv_interval nanosleep
                    clock_gettime clock_getres clock_nanosleep clock
                    stat lstat);
use 5.24.1;

our $VERSION = "1.0";

#TODO: why is SSL not working?! FUCK!
#TODO: LWP und InfluxHTTP durch Mojo POST ersetzen.

print_intro_header(); #Say hello to the world!

##################################################
#             Setting Up Internal Variables      #
##################################################

#
# RIS-Live parameters
#
my $prefix;
my $path;
my $type = "UPDATE";
my $moreSpecific = \1;

# Generate Settings hash for websocket connection.

my $settings = encode_json {
  type => 'ris_subscribe',
  data => {
       moreSpecific => $moreSpecific,
       type => $type,
       require => 'announcements'
  }
};

#
# Influx Stuff
# Connecting to InfluxDB and testing.
#
my $METRIC = "announce";
my $METRIC_RPKI = "announce_rpki";

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
# Retrieve the Patricia Trie Datastructure.
#

logger( "Retrieving Patricia Trie...");
my $pt_irr_v4 = retrieve('../stash/irr-patricia-v4.storable');
my $pt_irr_v6 = retrieve('../stash/irr-patricia-v6.storable');

my $pt_rpki_v4 = retrieve('../stash/rpki-patricia-v4.storable');
my $pt_rpki_v6 = retrieve('../stash/rpki-patricia-v6.storable');

logger("Done.");
#
# Storing Received Invalids for later analysis
#

my $invalid_log = "../stash/invalids.log";
open (my $INV_LOG, '>>', $invalid_log);

my $DEBUG = shift;


#
# Beginning of main
#

logger("Opening Websocket Connection...");
while(1) {
  my $ua  = Mojo::UserAgent->new;
  $ua->inactivity_timeout(0);
  $ua->websocket('ws://ris-live.ripe.net/v1/ws/?client=ba-test' => sub {
    my ($ua, $tx) = @_;
    logger('WebSocket handshake failed!', 'red') and return unless $tx->is_websocket;
    $tx->on(json => sub {
      my ($tx, $hash) = @_;
      digest_and_write($hash->{data});
      #$tx->finish;
    });
    $tx->on(finish => sub {
      my ($tx, $code, $reason) = @_;
      logger("WebSocket closed with status $code.", 'red');
    });
    $tx->send($settings);
  });
  logger("Websocket opened! Ris-Live is now feeding us!");
  Mojo::IOLoop->start unless Mojo::IOLoop->is_running;
}




#
# Subs for doing all the work
#

sub digest_and_write {
  #TODO: v6 vs v4!
  my $hash = shift;
  #Holds Influx-DB Lines.
  my @influx_lines;   
 
  my $origin_as = pop @{$hash->{path}};

  foreach my $announcement ( @{ $hash->{announcements} }[0] ) { #returns array of hashes
   
    my $tags = {
      #nexthop      => $announcement->{next_hop},
      #origin_as    => $origin_as,
      #peer         => $hash->{peer},
      source       => "ris",
      #peer_as      => $hash->{peer_asn},
      validity     => "valid" 
    };

    #Check received Announcements agains routing DBs
    my $irr_result = check_prefixes_irr($announcement->{prefixes}, $origin_as);

    #Check received Announcements against RPKI
    my $rpki_result = check_prefixes_rpki($announcement->{prefixes}, $origin_as);
 
    #
    # Build InfluxDB Data Line for IRR-Values
    #
    push @influx_lines, data2line($METRIC, $irr_result->{valid}, $tags );  
    $tags->{validity} = "invalid";
    push @influx_lines, data2line($METRIC, $irr_result->{invalid}, $tags);
    $tags->{validity} = "not_found";
    push @influx_lines, data2line($METRIC, $irr_result->{not_found}, $tags);
    $tags->{validity} = "valid_less_spec";
    push @influx_lines, data2line($METRIC, $irr_result->{valid_ls}, $tags);
    $tags->{validity} = "valid_implicit_coverage";
    push @influx_lines, data2line($METRIC, $irr_result->{valid_impl}, $tags);
    #push @influx_lines, data2line($METRIC, $prefix->{valid_ls}, $tags);
    
    #
    # Build Datalines for RPKI-Checks.
    #
    my $tags_rpki = {
      source => "ris",
      validity => "valid",
    };
    
    
    push @influx_lines, data2line($METRIC_RPKI, $rpki_result->{valid},  $tags_rpki);
    $tags_rpki->{validity} = "valid_ls";
    push @influx_lines, data2line($METRIC_RPKI, $rpki_result->{valid_ls},  $tags_rpki);
    $tags_rpki->{validity} = "invalid_ml";
    push @influx_lines, data2line($METRIC_RPKI, $rpki_result->{invalid_ml},  $tags_rpki);
    $tags_rpki->{validity} = "invalid";
    push @influx_lines, data2line($METRIC_RPKI, $rpki_result->{invalid},  $tags_rpki);
    $tags_rpki->{validity} = "not_found";
    push @influx_lines, data2line($METRIC_RPKI, $rpki_result->{not_found},  $tags_rpki);
    
  }
  
  $DB::single = 1;
  if ($DEBUG) {
    foreach (@influx_lines) {
      logger($_);
      }
  }
  my $res = $INFLUX->write(
   \@influx_lines,
   database    => "test_measure"
  ) unless ($DEBUG);
  say "Error writing dataset\n $res" unless ($res);
}  

#
# Check RPKI Validation Status of received prefixes
#

sub check_prefixes_rpki {
  my $prefix_hash = shift;
  my $origin_as = shift;
  $origin_as = "AS$origin_as";

  my $count_valid = 0;    #Valid
  my $count_valid_ls = 0; #Valid, covered becaus of max-length
  
  my $count_invalid = 0;
  my $count_invalid_ml = 0; #Invalid, Max-length!

  my $count_not_found = 0;

  #contains the hash returned by the Patricia Lookup
  my $pt_return;

  foreach my $prefix ( @{ $prefix_hash } ) {
    # Decide, whether we have v4/v6
    if ( (index $prefix, ":")  > 0) {
      $pt_return = $pt_rpki_v6->match_string($prefix);
    } else {
      $pt_return = $pt_rpki_v4->match_string($prefix);
    }
    
    my $prefix_length = ((split /\//, $prefix))[1]; 
    
    if ( $pt_return ) { #Lookup was successful. Prefix Exists in Tree
      if ($pt_return->{$origin_as}) {  #Found Origin AS as allowed AS...
        
        my $max_length = $pt_return->{$origin_as}->{max_length};

        if ($max_length == $prefix_length) { #Valid, exakt match
          logger("RPKI: $prefix with $origin_as is rpki-valid with an exact match!") if $DEBUG;
          $count_valid++;
        } elsif ($max_length > $prefix_length) { #Valid, not exact
          logger("RPKI: $prefix with $origin_as is rpki-valid with an less-spec match!") if $DEBUG;
          $count_valid_ls++;
        } elsif ($max_length < $prefix_length) { #Too specific!
          logger("RPKI: $prefix with $origin_as is rpki-invalid: $prefix_length is longer than max $max_length") if $DEBUG;
          $count_invalid_ml++;
        }
      } else { #Didn't find AS. Invalid... 
          logger("RPKI: $prefix with $origin_as is rpki-invalid: AS is not allowed to announce!") if $DEBUG;
          $count_invalid++;
      }
    } else { #Prefix not found... booring.
      logger("RPKI: $prefix with $origin_as is not found") if $DEBUG;
      $count_not_found++;   
    }
  }
  return {
    valid => $count_valid,
    valid_ls => $count_valid_ls,
    invalid  => $count_invalid,
    invalid_ml => $count_invalid_ml,
    not_found  => $count_not_found
  };
}
      
       
   
#
# Validate Prefixes using IRR-Data
#
sub check_prefixes_irr {
  my $prefix_hash = shift;
  my $origin_as = shift;
  $origin_as = "AS$origin_as";
  
  # Counter Variables.
  my $count_valid = 0;
  my $count_valid_ms = 0;
  my $count_valid_ls = 0;
  my $count_invalid = 0;
  my $count_not_found = 0;
  my $count_valid_impl = 0;

  # Contains the Patricia Lookup Return hash.
  my $pt_return;

  # Contains the length of the prefix;
  my $prefix_length;
  

  foreach my $prefix ( @{ $prefix_hash } ) {
    # Decide, whether we have v4/v6
    if ( (index $prefix, ":")  > 0) {
      $pt_return = $pt_irr_v6->match_string($prefix);
    } else {
      $pt_return = $pt_irr_v4->match_string($prefix);
    }
    
    $prefix_length = ((split /\//, $prefix))[1]; # Holds the prefix length of current prefix.

    if ( $pt_return) { #If defined, we found something. 
      if ( $pt_return->{origin}->{$origin_as} ) { #If the return Hash contains a key with the origin_as, it is valid
        if ( $pt_return->{length} == $prefix_length ) { # ro covers exactly
          logger("IRR: $prefix with $origin_as is valid, exact coverage!") if $DEBUG;
          $count_valid++;
        } else { #Is explicitely covered by a less-spec. Means: No exact route-object!
          logger("IRR: $prefix with $origin_as is valid, less-specific coverage!") if $DEBUG;
          $count_valid_ls++;
        }
      } else { # Might be invalid.
        if ( $pt_return->{implicit}->{$origin_as} ) { #Prefix is implicitely covered by less-spec. 
          $count_valid_impl++;
        } else { #We tried everything but... 
          say $INV_LOG "$origin_as announced invalid prefix $prefix!";
          $count_invalid++;
        }
      }
   } else {
      logger("IRR: $prefix with $origin_as is not found") if $DEBUG;
      $count_not_found++;     
   }
  }    
  return {
    valid     => $count_valid,
    valid_ms  => $count_valid_ms,
    valid_ls  => $count_valid_ls,
    valid_impl=> $count_valid_impl,
    invalid   => $count_invalid,
    not_found => $count_not_found
  };
}



#
# Subs for nicely formated logging.
#

sub print_header {
  my $db = shift;
  my $time = get_formated_time();
  my $msg =<<"EOF";
$time========================================
$time         Now Processing $db 
$time========================================
EOF
  print $msg;
}

sub get_formated_time {
  my ($sec, $min, $h) = localtime(time);
  my $time = sprintf '%02d:%02d:%02d : ', $h, $min, $sec;
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

sub print_intro_header {
  my $db = shift;
  my $time = get_formated_time();
  my $msg =<<"EOF";
           .            .                     .
                  _        .                          .            (
                 (_)        .       .                                     .
  .        ____.--^.
   .      /:  /    |                               +           .         .
         /:  `--=--'   .                                                .
  LS    /: __[\\==`-.___          *           .
       /__|\\ _~~~~~~   ~~--..__            .             .
       \\   \\|::::|-----.....___|~--.                                 .
        \\ _\\_~~~~~-----:|:::______//---...___
    .   [\\  \\  __  --     \\       ~  \\_      ~~~===------==-...____
        [============================================================-
        /         __/__   --  /__    --       /____....----''''~~~~      .
  *    /  /   ==           ____....=---='''~~~~ .
      /____....--=-''':~~~~                      .                .
      .       ~--~         Validator-Class route-destroyer. 
                     .     Version: $VERSION                              ..
                          .Github: https://git.io/fjQD5      .             +
        .     +              .                                       <=>
                                               .                .      .
   .                 *                 .                *                ` -
Graphic stolen from http://www.ascii-art.de/ascii/s/starwars.txt
By Phil Powell

EOF
  print $msg;
}


