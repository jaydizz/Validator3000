#!/usr/bin/perl 

=head1 NAME

Luke Databasewalker

=head1 ABSTRACT

This Tool is used to walk over different routing databases and generates a patricia trie for route validation. The tool can parse IRR-Files in RPSL-format and PRKI-Roas as exported by routinator3000 inr vrps format. 
The Patricia Trie holds IP-objects. On Match, a hashref is returned, holding validation-data.

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
use Storable qw(store dclone);
use Net::Patricia;
use Term::ANSIColor;
use Local::addrinfo qw( by_cidr mk_iprange_lite mk_iprange is_subset);
use Data::Dumper;
use 5.10.0;

my %opts;
getopts( 'i:o:db:r:p:', \%opts ) or usage();

our $VERSION = "1.0";

my $irr_dir  = $opts{i} || '../db/irr/';
my $irr_flag = defined $opts{b} ? $opts{b} : 1;
my $rpki_flag = defined $opts{r} ? $opts{r} : 1;
my $rpki_dir  = $opts{p} || '../db/rpki/';
my $output_dir = $opts{o} || '../stash/';
my $debug_flag = $opts{d} || undef;

print $irr_dir; 
my $output_files = {
  rpki_out_v4    => "$output_dir/rpki-patricia-v4.storable",
  rpki_out_v6    => "$output_dir/rpki-patricia-v6.storable",
  irr_out_v4    => "$output_dir/irr-patricia-v4.storable",
  irr_out_v6    => "$output_dir/irr-patricia-v6.storable",
};  

# Patricia Tree for lookup.
#my $pt_irr_v4 = new Net::Patricia;
#my $pt_irr_v6 = new Net::Patricia AF_INET6;

my $pt_rpki_v4 = new Net::Patricia;
my $pt_rpki_v6 = new Net::Patricia AF_INET6;

# Hashrefs for route-collection. Will be written into the trie.
my $stash_irr_v4 = {};
my $stash_irr_v6 = {};

my $stash_rpki_v4 = {};
my $stash_rpki_v6 = {};

my @irr_files = glob("$irr_dir*");
my @rpki_files = glob("$rpki_dir*");

# Remove directories and sh scripts.
@irr_files = grep { -f $_ } @irr_files;
@irr_files = grep {!/\.sh/} @irr_files;
@rpki_files = grep { -f $_ } @rpki_files;
@rpki_files = grep {!/\.sh/} @rpki_files;

############################################################################
#######################  MAIN ##############################################
############################################################################

print_intro_header();
#
# Iterating over all routing-dbs and parsing for route-objects.
# This populates the stashes for v4 and v6.
#
if ($irr_flag) {
  print_header("IRR");
  foreach my $file (@irr_files) {
    logger("Processing file: $file", 'yellow');
    my $start = time;
    my $counter = 0;
   
    open( my $FH, '<', $file ) or die "could not open file $file";
    #Temporary Variables to hold matches.
    my $net_addr; #everything before the /
    my $mask;     #everything after the /
    my $origin_as;
    my $routeobject_found;
    my $prefix;
    
    while (<$FH>) { 
      #Handling ipv4 objects. 
      if ($_ =~ /route:\s+([\d\.]+)\/(\d+)/) { 
        $net_addr = $1;
        $mask = $2;
        $prefix = "$1/$2";
        $routeobject_found = 4;
      } 
      if ($_ =~ /route6:+\s+([\d:\.a-f]+)\/(\d+)/) { 
        $net_addr = $1;
        $mask = $2;
        $prefix = "$1/$2";
        $routeobject_found = 6;
      }

      if ( $routeobject_found && $_ =~ /origin:\s+(AS\d+)/ ) {
        
        my $stash = $routeobject_found == 6 ? $stash_irr_v6 : $stash_irr_v4; 
        
        $stash->{$prefix}->{length} = $mask;
        $stash->{$prefix}->{origin}->{$1}->{source} = $file;
        $stash->{$prefix}->{prefix} = $prefix;
        
        #Additionally calculate base and end ip for easier sorting and containment checks. 
        my $ip_range = mk_iprange($prefix);
        $stash->{$prefix}->{ base_n } = $ip_range->{base_n};
        $stash->{$prefix}->{ last_n } = $ip_range->{last_n};
        $stash->{$prefix}->{ base_p } = $ip_range->{base_p};
        $stash->{$prefix}->{ last_p } = $ip_range->{last_p};
        $stash->{$prefix}->{ version } = $ip_range->{version};
        
        if ($debug_flag) {
          say "found $prefix : $origin_as";
        }
        $counter++;
        ($mask, $origin_as, $prefix) = undef; 
        
        #Add some verbosity
        if (($counter % 1000 ) == 0) {
          last if $debug_flag;
          my $duration = time - $start;
          logger_no_newline("processed $counter route-objects in $duration seconds");
        }
        $routeobject_found = 0;
      
      }
    }
    print "\n";
    close ($FH);
    my $duration = time - $start;
    logger("Done. It took $duration seconds to find $counter prefixes", 'green');
  }
  #
  # Now we write the stash_irr into a Patricia Trie. This is neccessary, because we have to store multiple
  # AS's as userdata. Storing the same prefix with different userdata directly into the Patricia Trie
  # just overwrites the old node. 
  #
  digest_hash_and_write($stash_irr_v4, "irr_out_v4");
  digest_hash_and_write($stash_irr_v6, "irr_out_v6");
  
}

#
#
#  Process RPKI shizzle.
#
#
#

if ($rpki_flag) {
  print_header("RPKI"); 
  #Preocess each rpki-file
  foreach my $file (@rpki_files) {
    logger("Processing file: $file");
    my $start = time;
    my $counter = 0; 
    open (my $FH, '<', $file);
    my $header = <$FH>; # stripping the header. 
    
    while (<$FH>) {
      my ($origin_as, $prefix, $max_length) = split /,/, $_;
     
      my $stash = (index $prefix, ":") > 0 ? $stash_rpki_v6 : $stash_rpki_v4; 
      
      $stash->{$prefix}->{origin}->{$origin_as}->{max_length} = $max_length;
      $stash->{$prefix}->{prefix} = $prefix;
      
      my $ip_range = mk_iprange($prefix);
      $stash->{$prefix}->{ base_n } = $ip_range->{base_n};
      $stash->{$prefix}->{ last_n } = $ip_range->{last_n};
      $stash->{$prefix}->{ base_p } = $ip_range->{base_p};
      $stash->{$prefix}->{ last_p } = $ip_range->{last_p};
      $stash->{$prefix}->{ version } = $ip_range->{version};
      
      if (($counter % 1000 ) == 0) {
        last if $debug_flag;
        my $duration = time - $start;
        logger_no_newline("processed $counter ROAs in $duration seconds");
      }
      $counter++;
    } 
    print "\n";  #Flush stdout.
    my $duration = time - $start;
    logger("Done. It took $duration seconds to find $counter prefixes", 'green');
  }
  
  digest_hash_and_write($stash_rpki_v4, "rpki_out_v4");
  digest_hash_and_write($stash_rpki_v6, "rpki_out_v6");

}

exit(0);
############################################################################
#######################  END OF MAIN  ######################################
############################################################################


#
# Sub that digests a given hashref. 
# First sorts the hasref by_cidr.
# Then resolv containment-issues: If a less-spec prefix covers a more spec, 
# all origin attributes are additionally inherited by the more-spec.
# Then builds a Patricia-Trie from the data and stores it to disk.
#

sub digest_hash_and_write {
  my $stash_ref = shift;
  my $case = shift;
  logger("Digesting $case Hash.");


  my $af_inet;
  my @sorted;

  logger("Sorting....");
  #First we need the hasref as an array for sorting. 
  foreach my $prefix (keys %$stash_ref) {
    push @sorted, $stash_ref->{$prefix};
  }

  @sorted = sort by_cidr @sorted; #Make it fit the name!
  
  $af_inet = $sorted[0]->{version};
  logger("Done. Got AF_INET $af_inet."); 
  logger("Resolving implicit Coverage."); 
  my $i = 0;
  #
  # Sorted is in format a,a1,a2,b,b1,b2...
  # All IP-spaces that can contain themselfes consecutetively stored.
  # As soon as the next prefix is not contained by the previous one, 
  # we can skip to the next one.
  #
  
  while ( $i <= $#sorted ) {
    my $j = $i + 1; #We look at the next entry in the sorted list.
    
    while ( $j <= $#sorted && is_subset($sorted[$j], $sorted[$i] ) ) {
      my $tmp_hash = dclone( $sorted[$i]->{origin} ); #Create a true copy of our hash.
      foreach my $as ( keys %$tmp_hash ) {
        #If an AS is already present in the origins, we don't want to mark it as implicit. Also if it already inherits an implicit, don't overwrite it.
        $tmp_hash->{$as}->{implicit} = 1 unless (defined $sorted[$j]->{origin}->{$as}) || (defined $tmp_hash->{$as}->{implicit}); 
      }
      %{ $sorted[$j]->{origin} } = ( %{ $sorted[$j]->{origin} }, %$tmp_hash ); #Append additional Origins.
      $j++;
    }
    $i++;
  }
  my $pt;
  logger("Creating and Writing the Trie.");
  if ($af_inet == AF_INET) {
   $pt = new Net::Patricia;
  } else {
   $pt = new Net::Patricia AF_INET6;
  }

  foreach my $prefix (@sorted) {
    $pt->add_string($prefix->{prefix}, $prefix);
  }
   
  my $store = $output_files->{$case};
  store ( $pt, $store );
  logger("Done.", 'green');
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

                    ____
                  (xXXXX|xx======---(-
                  /     |
                 /    XX|
                /xxx XXX|     LUKE DBWALKER PARSES IN LESS THAN TWO PARSECS.
               /xxx X   |
              / ________|
      __ ____/_|_|_______\\_
  ###|=||________|_________|_
      ~~   |==| __  _  __   /|~~~~~~~~~-------------_______
           |==| ||(( ||()| | |XXXXXXXX|                    >
      __   |==| ~~__~__~~__ \\|_________-------------~~~~~~~
  ###|=||~~~~~~~~|_______  |"
      ~~ ~~~~\\~|~|       /~
              \\ ~~~~~~~~~
               \\xxx X   |
                \\xxx XXX|
                 \\    XX|                
                  \\     |                Version: $VERSION.
                  (xXXXX|xx======---(-   Github: https://git.io/fjQD5
                    ~~~~                   
Graphic stolen from http://www.ascii-art.de/ascii/s/starwars.txt
By Phil Powell

EOF
  print $msg;
}

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
