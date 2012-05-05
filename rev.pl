#!/usr/bin/perl

##
# IPv6 automatic reverse/forward generator script by Aki Tuomi
# Released under the GNU GENERAL PUBLIC LICENSE v2
##

use strict;
use warnings;
use 5.005;
use Config::Simple;

# Configure domains in rev.cfg, note that you *must* configure
# SOA somewhere else. 
# 
my $Config = new Config::Simple('rev.cfg');
my $domaintable = $Config->get_block('domaintable');

my $ttl = 300;
my $debug = 0;
my $nodeprefix = 'node-';

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
        print "OK\t$dom has $prefix that is not divisable with 8\n";
        while(<>) {
            print "END\n";
        };
        exit 0;
    }
}

print "OK\tAutomatic reverse generator v1.0 starting\n";

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
            if (($qtype eq 'AAAA' || $qtype eq 'ANY') && $qname=~/${nodeprefix}([^.]*).(.*)/) {
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
                        $dname=~s/(.{4})/$1:/g;
                        chop $dname;

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
            print "LOG\tReceived a PING...\n";
        } elsif ($type eq 'AXFR') {
            print "LOG\tReceived an AXFR for $id\n";
        } else {
            print "FAIL\tUnsupported request\n";
        }
    }

    #end of data
    print "END\n";
}
