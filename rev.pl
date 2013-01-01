#!/usr/bin/env perl

##
# IPv6 automatic reverse/forward generator script by Aki Tuomi
# Enhanced/Modified by Simon Hitzemann
# Released under the GNU GENERAL PUBLIC LICENSE v2
##

use Modern::Perl;
use Config::Simple;

# RFC forces the [A-Z2-7] RFC-3548 compliant encoding
use MIME::Base32 qw( RFC );

# Configure domains in rev.cfg, note that you *must* configure SOA and NS records somewhere else. Please use an absolute path to the config file.
my $cfg = 'rev.cfg';
my $domaintable;

# If you set this to 1, you will unleash the SQL version, and it'll override your domain table. Just use the domainmetadata table and set the AUTOREV-PID attribute for your ip6.arpa zone pointing to the domain_id of the partnering zone
my $use_database = 0;
my $dsn          = "dbi:Pg:database=pdns;host=localhost";
my $dsn_user     = "pdns";
my $dsn_password = "password";

# Here you can update your query if you use a different than the default schema
my $q_domainmeta =
"SELECT domains.id,domains.name,domainmetadata.kind,domainmetadata.content FROM domainmetadata, domains WHERE domainmetadata.domain_id = domains.id AND domainmetadata.kind = 'AUTOREV-PID'";
my $q_domain = 'SELECT domains.name FROM domains WHERE id = ?';

my $ttl   = 300;
my $debug = 0;

# Set to 1 if you want to use Memoize. It needs more memory, but speeds queries up. It makes only sense though if you have a lot of different subnets with identical host parts.
my $memoize    = 0;
my $nodeprefix = 'node-';
my $VERSION    = "0.6";

# End of configuration.

if ( 1 == $memoize ) {
    use Memoize;
    memoize('MIME::Base32::encode');
    memoize('MIME::Base32::decode');
}

sub rev_to_prefix {
    my $rev = shift;
    $rev =~ s/\Q.ip6.arpa\E$//i;
    my $prefix = join '', ( reverse split /\./, $rev );
    $prefix =~ s/(.{4})/$1:/g;
    $prefix =~ s/:$//;
    return $prefix;
}

# Build domaintable from data in the database instead of the cfg file
sub load_domaintable {

    # Connect to the configured DB
    my $d = DBI->connect( $dsn, $dsn_user, $dsn_password );
    $domaintable = {};
    my $tmptable = {};
    my $stmt     = $d->prepare($q_domainmeta);
    $stmt->execute or return;

    # Collect the involved zones
    if ( $stmt->rows ) {
        my ( $i_domain_id, $s_domain, $s_kind, $s_content );
        $stmt->bind_columns(
            ( \$i_domain_id, \$s_domain, \$s_kind, \$s_content ) );
        while ( $stmt->fetch ) {

            # If we end up here, you defined AUTOREV-PID for non ip6.arpa zones
            next if ( $s_domain =~ /ip6\.arpa$/ );
            if ( $s_kind eq 'AUTOREV-PID' ) {
                $tmptable->{$i_domain_id}->{'domain'}     = $s_domain;
                $tmptable->{$i_domain_id}->{'partner_id'} = int($s_content);
            }
        }
    }
    $stmt->finish;
    $stmt = $d->prepare($q_domain);

    # Now we can build the right domaintable structure
    while ( my ( $d_id, $d_data ) = each %$tmptable ) {
        $stmt->execute( ( $d_data->{'partner_id'} ) ) or next;
        if ( $stmt->rows == 0 ) {
            print "LOG\tWARNING: Failed to locate prefix for ",
              $d_data->{'domain'}, "\n";
            next;
        }
        my ($prefix) = $stmt->fetchrow_array;
        $prefix = rev_to_prefix($prefix);
        $domaintable->{ $d_data->{'domain'} } = $prefix;
    }
    $stmt->finish;
    $d->disconnect;
}

# From now on we flush the output regularly.
local $| = 1;

# Perform handshake with PowerDNS. We support ABI versions 1 and 2 since we do check for number of arguments >= 6 and do not use fields 7 and 8. Version 3 would need a different answer format.
my $helo = <>;
chomp($helo);

# Game has changed, check for ABI version 3 only
unless ( $helo =~ /HELO\t3/ ) {
    print "FAIL\n";
    while (<>) { }
    exit;
}

# If we use the database for generating the domaintable hash we will do it
# now.
if ($use_database) {
    print "LOG\tLoading domains from database\n" if ($debug);
    require DBI;
    load_domaintable;
}
else {
    print "LOG\tLoading domains from config file\n" if ($debug);
    require Config::Simple;
    my $Config = Config::Simple->new();
    $Config->read($cfg);
    $domaintable = $Config->get_block('domaintable');
}

my $domains;

# Build domain table configuration from domaintable hash.
while ( my ( $dom, $prefix ) = each %$domaintable ) {
    $domains->{$dom} = $prefix;

    # Convert the subnet to revnibbles by removing the colons first.
    my $tmp = $prefix;
    $tmp =~ s/://g;
    $prefix = $tmp;

    # Now calculate the number of bits needed.
    my $bits = length($tmp) * 4;

    # If the number of bits is not dividable by 16 ignore it (I yet have to
    # understand what bad stuff would happen)
    unless ( 0 == ( $bits % 16 ) ) {
        print
          "LOG\t$dom has $prefix which cannot be divided by 16 - ignoring\n";
        next;
    }

    # Now reverse the string and put dots in between.
    $tmp = join '.', reverse split //, $tmp;
    $tmp =~ s/^[.]//;
    $tmp =~ s/[.]$//;

    # Define forward lookup entry
    $domains->{$dom} = { prefix => $prefix, bits => $bits };

    # and the respective reverse lookup ntry
    $domains->{"$tmp.ip6.arpa"} = { domain => $dom, bits => $bits };
}

print "OK\tAutomatic reverse generator v${VERSION} starting\n";

while (<>) {
    chomp;
    my @arguments = split(/\t/);

    # Check if there are 2 or 8 arguments. (2 for PING etc, 8 for Q)
    unless ( @arguments == 8 || @arguments == 2 ) {
        print "LOG\tPowerDNS sent unparseable line\n";
        print "FAIL\n";
        next;
    }

    # With 8 arguments it must be a Q request.
    if ( @arguments == 8 ) {

        my ( $type, $qname, $qclass, $qtype, $id, $ip, $localip, $endssubnet )
          = @arguments;

        # Make sure it actually is a Q
        if ( $type eq 'Q' ) {
            print "LOG\t$qname $qclass $qtype?\n" if ($debug);

# Check if this is a forward lookup, since PowerDNS mostly sends ANY as request type we need to check if the configured nodeprefix is present.
            if ( ( $qtype eq 'AAAA' || $qtype eq 'ANY' )
                && $qname =~ /^${nodeprefix}([^.]*).(.*)/ )
            {
                my $node = $1;
                my $dom  = $2;
                print "LOG\t$node $dom and ", $domains->{$dom}{prefix}, "\n"
                  if ($debug);

                # Check if it is our domain and if the node name looks sane
                if ( $domains->{$dom} and $node =~ m/^[A-Za-z2-7]+$/ ) {
                    my $n = ( 128 - $domains->{$dom}{bits} ) / 5;
                    while ( length($node) < $n ) {
                        $node = join '', "a", $node;
                    }

                    # Convert from Base 32 back to Base 16
                    $node = unpack( "H*", MIME::Base32::decode( uc($node) ) );

       # Check if the converted host part has the correct length for this domain
                    $n = ( 128 - $domains->{$dom}{bits} ) / 4;
                    if ( length($node) == $n ) {

                        # Take the host part we just calculated.
                        my $dname = $node;

                        # Take the prefix from the hashtable.
                        my $tmp = $domains->{$dom}{prefix};

                        # Concatenate them
                        $dname = $tmp . $dname;

# Put in the colons. Yes, this looks horrbily insane, but is roughly 250% faster than the previosu regexp way.
                        $dname = join ':', substr( $dname, 0, 4 ),
                          substr( $dname, 4,  4 ), substr( $dname, 8,  4 ),
                          substr( $dname, 12, 4 ), substr( $dname, 16, 4 ),
                          substr( $dname, 20, 4 ), substr( $dname, 24, 4 ),
                          substr( $dname, 28, 4 );

# Send out the reply (0 are the hardcoded bits from ednssubnet used for the reply, 1 says the answer is auth)
                        print
"LOG\t0\t1\t$qname\t$qclass\tAAAA\t$ttl\t$id\t$dname\n"
                          if ($debug);
                        print
"DATA\t0\t1\t$qname\t$qclass\tAAAA\t$ttl\t$id\t$dname\n";
                    }
                }

# Check if this is a reverse lookup. Since PowerDNS mostly asks for ANY we need to check it we check for ip6.arpa at the end of the queried name.
            }
            elsif ( ( $qtype eq 'PTR' || $qtype eq 'ANY' )
                && $qname =~ /(.*\.ip6\.arpa$)/ )
            {
                my $node = $1;

                # Check if this domain is served by us.
                foreach ( keys %$domains ) {

                    # For each configured zone we extract the zone name
                    my $key = $_;
                    my $dom = $domains->{$_}{domain};

# Now we check if the zone name is part of the hostname that we've been asked for
                    my $index = index( $node, $key );
                    if ( $index != -1 ) {
                        $qname = $node;

# Since we already know where in the qname the zone name start, we can remove it easily from the string.
                        $node = substr( $qname, 0, $index - 1 );

                        # Reverse the node name and remove the dots
                        $node = join '', reverse split /\./, $node;

                        # Convert from Base 16 to Base 32
                        $node =
                          lc( MIME::Base32::encode( pack( "H*", $node ) ) );

# There might have been many leading zeroes which convert to y, we remove those as we add them again during the forward lookup
                        $node =~ s/^a*//;

                   # Special case: node IP was all zeroes (would that be valid?)
                        $node = 'a' if ( $node eq '' );

# Send out the reply (0 are the hardcoded bits from ednssubnet used for the reply, 1 says the answer is auth)
                        print
"LOG\t0\t1\t$qname\t$qclass\tPTR\t$ttl\t$id\t$nodeprefix$node.$dom\n"
                          if ($debug);
                        print
"DATA\t0\t1\t$qname\t$qclass\tPTR\t$ttl\t$id\t$nodeprefix$node.$dom\n";
                    }
                }
            }
        }
        else {
            # The type of the query was not Q
            print "FAIL\tUnsupported request\n";
        }
    }
    elsif ( @arguments == 2 ) {

        # This must be one of requests which need one argument (PING, AXFR)
        my ( $type, $id ) = @arguments;
        if ( $type eq 'PING' ) {

            # We only need to reply with END to PING
            print "LOG\tReceived a PING...\n" if ($debug);
        }
        elsif ( $type eq 'AXFR' ) {

   # We do not support AXFR, but shall not send out a FAIL according to the docs
            print "LOG\tReceived an AXFR for $id\n" if ($debug);
        }
        else {
            # This was neither PING nor AXFR, send out FAIL
            print "FAIL\tUnsupported request\n";
        }
    }

    #We are done with processing this request and can finalize it by sending END
    print "END\n";
}
