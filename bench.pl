#!/usr/bin/perl


use Benchmark qw(:all);

cmpthese (0, {
        'join' => sub {
            my $node="bla";
            while (length($node)<56) {
                $node = join '', "y", $node;
            }
        },
        'equals' => sub {
            my $node="bla";
            while (length($node)<56) {
                $node = "y$node";
            }
        },
        'dot' => sub {
            my $node="bla";
            while (length($node)<56) {
                $node = 'y' . $node;
            }
        }
    });

cmpthese (0, {
        'regexp' => sub {
            my $key="f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa";
            my $node="4.a.9.7.b.9.e.f.0.0.0.0.0.0.0.0.f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa";
            my $qname;
            if ($node=~/(.*)\Q.$key\E$/) {
                $qname = $node;
                $node = $1;
            }
        },
        'substr' => sub {
            my $key="f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa";
            my $node="4.a.9.7.b.9.e.f.0.0.0.0.0.0.0.0.f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa";
            my $qname;
            my $index = index($node, $key);
            if ($index != -1) {
                $qname = $node;
                $node = substr($qname, 0, $index-1);
            }
        }
    });

cmpthese (0, {
        'splitreg' => sub {
            my $string ="Q\t4.a.9.7.b.9.e.f.0.0.0.0.0.0.0.0.f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa\tIN\tANY\t-1\t127.0.0.1\n";
            chomp $string;
            my @arr=split(/[\t ]+/, $string);
        },
        'splitplain' => sub {
            my $string ="Q\t4.a.9.7.b.9.e.f.0.0.0.0.0.0.0.0.f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa\tIN\tANY\t-1\t127.0.0.1\n";
            chomp $string;
            my @arr=split(/\t/, $string);
        }
    });

cmpthese (0, {
        'regexp' => sub {
            my $str = 'deadbeefcafebabe73311234';
            $str =~ s/(.{4})/$1:/g;
            chop $str;
        } ,
        'join' => sub {
            my $str = 'deadbeefcafebabe73311234';
            $str = join ':', substr($str, 0, 4), substr($str, 4, 4), substr($str, 8, 4), substr($str, 12, 4), substr($str, 16, 4), substr($str, 20, 4), substr($str, 24, 4), substr($str, 28, 4);
        }
    });