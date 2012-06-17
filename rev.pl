#!/usr/bin/perl

##
# IPv6 automatic reverse/forward generator script by Aki Tuomi
# Released under the GNU GENERAL PUBLIC LICENSE v2
##

use strict;
use warnings;
use 5.005;
use Config::Simple;
use DBI;
use Data::Dumper;

# Configure domains in rev.cfg, note that you *must* configure
# SOA somewhere else. 
# 
my $Config = new Config::Simple('rev.cfg');
my $domaintable = $Config->get_block('domaintable');

# Of course, if the above feels somewhat tedious, you can always use 
# SQL connection to configure things. if you set this to 1, you 
# unleash the SQL version, and it'll override your domain table. 
my $use_database = 0;
my $dsn = "dbi:Pg:database=pdns;host=localhost";
my $dsn_user = "pdns";
my $dsn_password = "password";

# if you got special schema, do update this query
my $q_domainmeta = "SELECT domains.id,domains.name,domainmetadata.kind,domainmetadata.content FROM domainmetadata, domains WHERE domainmetadata.domain_id = domains.id AND domainmetadata.kind = 'AUTOREV-PID'";
my $q_domain = 'SELECT domains.name FROM domains WHERE id = ?';

my $ttl = 300;
my $debug = 0;
# Set to 0 if you do not want to use Memoize
# It needs more memory, but speeds queries up
# Makes only sense if you have a lot of different subnets
# with identical host parts.
my $memoize = 0;
my $nodeprefix = 'node-';
my $VERSION = "0.3";

# end of configuration.

# These helpers are for 16->32 and 32->16 conversions
my %v2b = do {
    my $i = 0;
    map { $_ => sprintf( "%05b", $i++ ) } qw(y b n d r f g 8 e j k m c p q x o t 1 u w i s z a 3 4 5 h 7 6 9);
};
my %b2v = reverse %v2b;

sub from32 {
    my $str = shift;
    $str =~ tr/ybndrfg8ejkmcpqxot1uwisza345h769//cd;
    $str =~ s/(.)/$v2b{$1}/g;
    my $padlen = (length $str) % 8;
    $str =~ s/0{$padlen}\z//;
    return scalar pack "B*", $str;
}

sub to32 {
    my $str = shift;
    my $ret = unpack "B*", $str;
    $ret .= 0 while ( length $ret ) % 5;
    $ret =~ s/(.....)/$b2v{$1}/g;
    return $ret;
}

sub from16 {
    my $str = shift;
    $str =~ tr/0-9a-f//cd;
    return scalar pack "H*", lc $str;
}

sub to16 {
    my $str = shift;
    return unpack "H*", $str;
}

if (1 == $memoize) {
    use Memoize;
    memoize('from32');
    memoize('to32');
    memoize('from16');
    memoize('to16');
}

sub rev2prefix {
  my $rev = shift;
  $rev =~ s/\Q.ip6.arpa\E$//i;
  my $prefix = join '', (reverse split /\./, $rev);
  # then convert back into prefix
  $prefix=~s/(.{4})/$1:/g;
  $prefix=~s/:$//;
  return $prefix;
}

# loads domain table from SQL
sub load_domaintable {
   my $d = DBI->connect($dsn, $dsn_user, $dsn_password);
   $domaintable = {};
   my $tmptable = {};
   my $stmt = $d->prepare($q_domainmeta);
   $stmt->execute or return;

   if ($stmt->rows) {
      my ($i_domain_id, $s_domain, $s_kind, $s_content);
      $stmt->bind_columns((\$i_domain_id, \$s_domain, \$s_kind, \$s_content));
      while($stmt->fetch) {
         # what are we looking here... 
         next if ($s_domain =~ /ip6\.arpa$/);
         if ($s_kind eq 'AUTOREV-PID') {
           $tmptable->{$i_domain_id}->{'domain'} = $s_domain;
           $tmptable->{$i_domain_id}->{'partner_id'} = int($s_content);
         }
      }
   }
   $stmt->finish;

   $stmt = $d->prepare($q_domain);
  
   # then we build the domaintable for real 
   while(my ($d_id, $d_data) = each %$tmptable) {
      $stmt->execute(($d_data->{'partner_id'})) or next;
      if ($stmt->rows == 0) {
         print "LOG\tWARNING: Failed to locate prefix for ",$d_data->{'domain'},"\n";
         next;
      }

      my ($prefix) = $stmt->fetchrow_array;
      $prefix = rev2prefix($prefix);
      $domaintable->{$d_data->{'domain'}} = $prefix;
   }

   $stmt->finish;
   $d->disconnect;
}

$|=1;

# perform handshake. we support ABI 1
# since we do check for number of arguments >= 6 
# and do not use fields 7 and 8
# we can support ABI version 2
# ABI version 3 needs a different answer format
my $helo = <>;
chomp($helo);

unless ($helo =~ /HELO\t[12]/) {
    print "FAIL\n";
    while(<>) {};
    exit;
}

if ($use_database) {
  print "LOG\tLoading domains from database\n";
  load_domaintable;
}

my $domains;

# Build domain table based on configuration
while(my ($dom,$prefix) = each %$domaintable) {
    $domains->{$dom} = $prefix;

    # build reverse lookup domain
    my $tmp = $prefix;
    $tmp=~s/://g;
    $prefix = $tmp;

    # this is needed for compression
    my $bits = length($tmp)*4;

    $tmp = join '.', reverse split //,$tmp;
    $tmp=~s/^[.]//;
    $tmp=~s/[.]$//;

    # forward lookup
    $domains->{$dom} = { prefix => $prefix, bits => $bits };
    # reverse lookup
    $domains->{"$tmp.ip6.arpa"} = { domain => $dom, bits => $bits };

    # ensure the n. of bits is divisable by 16 (otherwise bad stuff happens)
    unless (($bits%16)==0) {
        print "OK\t$dom has $prefix that cannot be divided by 16\n";
        while(<>) {
            print "END\n";
        };
        exit 0;
    }
}

print "OK\tAutomatic reverse generator v${VERSION} starting\n";

while(<>) {
    chomp;
    my @arr=split(/\t/);
    if(@arr<6 && @arr>2) {
        print "LOG\tPowerDNS sent unparseable line\n";
        print "FAIL\n";
        next;
    }

    # Must be a Q request
    if (@arr>5) {

        # get the request
        my ($type,$qname,$qclass,$qtype,$id,$ip)=@arr;

        if ($type eq 'Q') {

            print "LOG\t$qname $qclass $qtype?\n" if ($debug);

            # forward lookup handler
            if (($qtype eq 'AAAA' || $qtype eq 'ANY') && $qname=~/^${nodeprefix}([^.]*).(.*)/) {
                my $node = $1;
                my $dom = $2;

                print "LOG\t$node $dom and ", $domains->{$dom}{prefix}, "\n" if ($debug);

                # make sure it's our domain first and reasonable
                if ($domains->{$dom} and $node=~m/^[ybndrfg8ejkmcpqxot1uwisza345h769]+$/) {
                    my $n = (128 - $domains->{$dom}{bits}) / 5;

                    while(length($node) < $n) {
                        $node = join '', "y", $node;
                    }

                    $node = to16(from32($node));

                    $n = (128 - $domains->{$dom}{bits}) / 4;

                    # only process correct length
                    if (length($node) == $n) {
                        # convert
                        my $dname = $node;
                        # hmm
                        my $tmp = $domains->{$dom}{prefix};

                        # build whole IPv6 address and add : to correct placs
                        $dname = $tmp.$dname;
                        $dname = join ':', substr($dname, 0, 4), substr($dname, 4, 4), substr($dname, 8, 4), substr($dname, 12, 4), substr($dname, 16, 4), substr($dname, 20, 4), substr($dname, 24, 4), substr($dname, 28, 4);

                        # reply with value
                        print "LOG\t$qname\t$qclass\tAAAA\t$ttl\t$id\t$dname\n" if ($debug);
                        print "DATA\t$qname\t$qclass\tAAAA\t$ttl\t$id\t$dname\n";
                    }
                }
                # reverse lookup
            } elsif (($qtype eq 'PTR' || $qtype eq 'ANY') && $qname=~/(.*\.arpa$)/) {
                my $node = $1;

                # look for our domain
                foreach(keys %$domains) {
                    my $key = $_;
                    my $dom = $domains->{$_}{domain};
                    my $index = index($node, $key);
                    if ($index != -1) {
                        $qname = $node;
                        $node = substr($qname, 0, $index-1);

                        $node = join '', reverse split /\./, $node;

                        # recode to base32
                        $node = to32(from16($node));

                        # compress
                        $node =~ s/^y*//;
                        $node = 'y' if ($node eq '');

                        print "LOG\t$qname\t$qclass\tPTR\t$ttl\t$id\t$nodeprefix$node.$dom\n" if ($debug);
                        print "DATA\t$qname\t$qclass\tPTR\t$ttl\t$id\t$nodeprefix$node.$dom\n";
                    }
                }
            }
        } else {
            print "FAIL\tUnsupported request\n";
        }
    } elsif (@arr<3) {
        my ($type,$id)=@arr;
        if ($type eq 'PING') {
            print "LOG\tReceived a PING...\n" if ($debug);
        } elsif ($type eq 'AXFR') {
            print "LOG\tReceived an AXFR for $id\n" if ($debug);
        } else {
            print "FAIL\tUnsupported request\n";
        }
    }

    #end of data
    print "END\n";
}
