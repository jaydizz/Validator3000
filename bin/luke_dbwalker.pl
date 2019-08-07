#!/usr/bin/perl 

=head1 NAME
Luke Databasewalker

=head1 ABSTRACT

Tool to walk over IRR-Databases and extract route-objects. Builds a giant perl-hashmap to be loaded into RAM to be able to compute validity of Routing-Updates in Realtime. 
Can additionally process vrps-data as exported by routinator.
=head1 SYNOPSIS

./luke_dbwalker.pl -i <directory> -o <stash>

If no arguments are given, ../db and ../stash will be used

=cut

use strict;
use warnings;
use Getopt::Std;
use Storable;
use NetAddr::IP;
use Net::Patricia;
use Term::ANSIColor;
use Local::addrinfo qw( by_cidr mk_iprange_lite mk_iprange is_subset);

use 5.10.0;

my %opts;
getopts( 'i:o:d:b:r', \%opts ) or usage();

my $irr_dir  = $opts{i} || '../db/irr/*';
my $irr_flag = $opts{b} ||  1;
my $rpki_flag = $opts{r} || 1;
my $rpki_dir  = $opts{p} || '../db/rpki/*';
my $output_dir = $opts{o} || '../stash/';
my $debug_flag = $opts{d} || undef;

my $rpki_out_v4 = "$output_dir/rpki-patricia-v4.storable";
my $rpki_out_v6 = "$output_dir/rpki-patricia-v6.storable";

my $irr_out_v4 = "$output_dir/irr-patricia-v4.storable";
my $irr_out_v6 = "$output_dir/irr-patricia-v6.storable";

# Patricia Tree for lookup.
#my $pt_irr_v4 = new Net::Patricia;
#my $pt_irr_v6 = new Net::Patricia AF_INET6;

my $pt_rpki_v4 = new Net::Patricia;
my $pt_rpki_v6 = new Net::Patricia AF_INET6;

# Hashrefs for route-collection. Will be written into the trie.
my $stash_irr_v4;
my $stash_irr_v6;

my $stash_rpki_v4;
my $stash_rpki_v6;

my @irr_files = glob($irr_dir);
my @rpki_files = glob($rpki_dir);

#
# Iterating over all routing-dbs and parsing for route-objects.
# This populates the stashes for v4 and v6.
#
if ($irr_flag) {
  foreach my $file (@irr_files) {
    say "Processing file: $file";
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
        if ($routeobject_found == 4) {
          $stash_irr_v4->{$prefix}->{length} = $mask;
          $stash_irr_v4->{$prefix}->{origin}->{$1} = 1;
          $stash_irr_v4->{$prefix}->{prefix} = $prefix;
          
          #Additionally calculate base and end ip for easier sorting and containment checks. 
          my $ip_range = mk_iprange($prefix);
          $stash_irr_v4->{$prefix}->{ base_n } = $ip_range->{base_n};
          $stash_irr_v4->{$prefix}->{ last_n } = $ip_range->{last_n};
          $stash_irr_v4->{$prefix}->{ base_p } = $ip_range->{base_p};
          $stash_irr_v4->{$prefix}->{ last_p } = $ip_range->{last_p};
          $stash_irr_v4->{$prefix}->{ version } = $ip_range->{version};

        } else {
          $stash_irr_v6->{$prefix}->{length} = $mask;
          $stash_irr_v6->{$prefix}->{origin}->{$1} = 1;
          $stash_irr_v6->{$prefix}->{prefix} = $prefix;
          
          #Additionally calculate base and end ip for easier sorting and containment checks. 
          my $ip_range = mk_iprange($prefix);
          $stash_irr_v6->{$prefix}->{ base_n } = $ip_range->{base_n};
          $stash_irr_v6->{$prefix}->{ last_n } = $ip_range->{last_n};
          $stash_irr_v6->{$prefix}->{ base_p } = $ip_range->{base_p};
          $stash_irr_v6->{$prefix}->{ last_p } = $ip_range->{last_p};
          $stash_irr_v6->{$prefix}->{ version } = $ip_range->{version};
        }
        
        if ($debug_flag) {
          say "found $prefix : $origin_as";
        }
        $counter++;
        ($mask, $origin_as, $prefix) = undef; 
        
        #Add some verbosity
        if (($counter % 1000 ) == 0) {
          last if $debug_flag;
          my $duration = time - $start;
          print "processed $counter route-objects in $duration seconds           \r";
          STDOUT->flush();
        }
        $routeobject_found = 0;
      
      }
    }
    close ($FH);
    my $duration = time - $start;
    say color('green');
    say "Done. It took $duration seconds to find $counter prefixes";
    say color('reset');
  }
  #
  # Now we write the stash_irr into a Patricia Trie. This is neccessary, because we have to store multiple
  # AS's as userdata. Storing the same prefix with different userdata directly into the Patricia Trie
  # just overwrites the old node. 
  #
  digest_irr_and_write($stash_irr_v4);
  digest_irr_and_write($stash_irr_v6);
  
}

#
# Sub that digests a given hashref. 
# First sorts the hasref by_cidr.
# Then resolv containment-issues: If a less-spec prefix covers a more spec, 
# all origin attributes are additionally inherited by the more-spec.
# Then builds a Patricia-Trie from the data and stores it to disk.
#

sub digest_irr_and_write {
  my $stash_ref = shift;

  my $af_inet;
  my @sorted;

  #First we need the hasref as an array for sorting. 
  foreach my $prefix (keys %$stash_ref) {
    push @sorted, $stash_ref->{$prefix};
  }

  @sorted = sort by_cidr @sorted; #Make it fit the name!
  
  $af_inet = $sorted[0]->{version};
  
  my $i = 0;
  #
  # Sorted is in format a,a1,a2,b,b1,b2...
  # All IP-spaces that can contain themselfes consecutetively stored.
  # As soon as the next prefix is not contained by the previous one, 
  # we can skip to the next one.
  #

  while ( $i < $#sorted ) {
    my $j = $i + 1; #We look at the next entry in the sorted list.
    while ( is_subset($sorted[$j], $sorted[$i] ) ) {
      $sorted[$j]->{less_spec} = $sorted[$i]->{origin};
      $j++;
    }
    $i = $j++;
  }

  my $pt;

  if ($af_inet == AF_INET) {
   $pt = new Net::Patricia;
  } else {
   $pt = new Net::Patricia AF_INET6;
  }

  foreach my $prefix (@sorted) {
    $pt->add_string($prefix->{prefix}, $prefix);
  }
   
  my $store = $af_inet == AF_INET ? $irr_out_v4 : $irr_out_v6;
  store ( $pt, $store );
}
      


if ($rpki_flag) {
  say "Now walking over rpki dir";
  
  #Preocess each rpki-file
  foreach my $file (@rpki_files) {
    say "Processing $file";
    open (my $FH, '<', $file);
    my $header = <$FH>; # stripping the header. 
    
    
    while (<$FH>) {
      my ($origin_as, $prefix, $max_length) = split /,/, $_;
      
      if ( (index $prefix, ":") > 0) {#v6
        $stash_rpki_v6->{$prefix}->{$origin_as}->{max_length} = $max_length;
        $stash_rpki_v6->{$prefix}->{prefix} = $prefix;
      } else { 
        $stash_rpki_v4->{$prefix}->{$origin_as}->{max_length} = $max_length;
        $stash_rpki_v4->{$prefix}->{prefix} = $prefix;
      }
    } 
  } 
  
  # Contruct the tree
  foreach my $prefix ( sort keys %$stash_rpki_v4 ) {
    eval {
      $pt_rpki_v4->add_string($prefix, $stash_rpki_v4->{$prefix});
    }; if ($@) {
      die "FUCK! $prefix, $stash_rpki_v4->{$prefix}";
    }
  }
  foreach my $prefix ( keys %$stash_rpki_v6 ) {
    $pt_rpki_v6->add_string($prefix, $stash_rpki_v6->{$prefix});
  }


  store ($pt_rpki_v4, "$rpki_out_v4");
  store ($pt_rpki_v6, "$rpki_out_v6");
} 
