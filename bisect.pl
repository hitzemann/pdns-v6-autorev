#!/usr/bin/perl

use strict;
use warnings;
use 5.005;
use IPC::Open3;
use Symbol 'gensym'; 

my($wr, $rd, $err);
$err = gensym;

my $pid;

$|=1;
sub speak {
    my $out = shift;
    print $wr "$out\n";
}

sub expect  {
    my $in = shift;
    my $data = <$rd>;
    chomp($data);
    return $data=~m/$in/;
}

sub speak_and_expect {
    my $out = shift;
    my $in  = shift;
    speak $out;
    return expect $in;
}

sub result {
    my $text = shift;
    my $result = shift;

    $result and return 0;
    $result or return 1;
}

sub harness {
    # Use this for profiling, run dprofpp after test.pl is done
    #$pid = open3($wr, $rd, $err, "/opt/local/bin/perl -d:DProf rev.pl");
    $pid = open3($wr, $rd, $err, "./rev.pl");
}

sub finish {
    close $wr;
    close $rd;
    waitpid($pid,0);
}

harness;
my $rval=0;

$rval += (result "Open", speak_and_expect "HELO\t1","^OK.*");
speak "Q\t4.a.9.7.b.9.e.f.0.0.0.0.0.0.0.0.f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa\tIN\tANY\t-1\t127.0.0.1";
$rval += (result "Reverse ",expect "DATA\t4.a.9.7.b.9.e.f.0.0.0.0.0.0.0.0.f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa\tIN\tPTR\t300\t-1\tnode-86uph4e.dyn.test");
expect "END";
speak "Q\tnode-86uph4e.dyn.test\tIN\tANY\t-1\t127.0.0.1";
$rval += (result "Forward ",expect "DATA\tnode-86uph4e.dyn.test\tIN\tAAAA\t300\t-1\tfe80:0000:0250:56ff:0000:0000:fe9b:79a4");
expect "END";
speak "PING";
$rval += (result "PING ",expect "END");
speak "AXFR\t1";
$rval += (result "AXFR ",expect "END");

finish;

if (0 < $rval) {
    $rval = 1;
}
exit $rval;
