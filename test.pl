use Modern::Perl;
use IPC::Open3;
use Symbol 'gensym'; 
my $method = eval "use Time::Hires qw( time ); 1" ? "hires" : "stock";

print "Using ${method} time() call\n";

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

    $result and print "$text OK\n";
    $result or print "$text FAIL\n";
}

sub harness {
    # Use this for profiling, run dprofpp after test.pl is done
    #$pid = open3($wr, $rd, $err, "/opt/local/bin/perl -d:DProf rev.pl");
    #$pid = open3($wr, $rd, $err, "/opt/local/bin/perl -d:SmallProf rev.pl");
    $pid = open3($wr, $rd, $err, "./rev.pl");
}

sub finish {
    close $wr;
    close $rd;
    waitpid($pid,0);
}

harness;

result "Open", speak_and_expect "HELO\t3","^OK.*";

speak "Q\t4.a.9.7.b.9.e.f.0.0.0.0.0.0.0.0.f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa\tIN\tANY\t-1\t127.0.0.1\t127.0.0.1\t127.0.0.1";
result "Reverse ",expect "DATA\t0\t1\t4.a.9.7.b.9.e.f.0.0.0.0.0.0.0.0.f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa\tIN\tPTR\t300\t-1\tnode-h6tn42i.dyn.test";
expect "END";
speak "Q\tnode-h6tn42i.dyn.test\tIN\tANY\t-1\t127.0.0.1\t127.0.0.1\t127.0.0.1";
result "Forward ",expect "DATA\t0\t1\tnode-h6tn42i.dyn.test\tIN\tAAAA\t300\t-1\tfe80:0000:0250:56ff:0000:0000:fe9b:79a4";
expect "END";

my @list;

map {
push @list, (join '.', split //, sprintf("%04x",$_));
} (0 .. 0xffff);

# speed test
print "Testing speed for 0000 to ffff PTRs (this will take some time)";
my $t0 = time;
map { 
print $wr "Q\t$_.b.9.e.f.0.0.0.0.0.0.0.0.f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa\tIN\tANY\t-1\t127.0.0.1\t127.0.0.1\t127.0.0.1\n";
my $scrap = <$rd>;
$scrap = <$rd>;
} @list;
my $t = time - $t0;

print "OK\n";
my $qps = 65536/$t;

print "PTR Performance was $qps q/s\n";

@list = [];
open(NOD, '<nodes.txt');
while (my $line = <NOD>) {
    chomp $line;
    push @list, $line;
}
close(NOD);
shift @list;

print "Testing speed for 0000 to ffff AAAAs (this will take some time)";
$t0 = time;
map {
print $wr "Q\tnode-$_.dyn.test\tIN\tANY\t-1\t127.0.0.1\t127.0.0.1\t127.0.0.1\n";
my $scrap = <$rd>;
$scrap = <$rd>;
} @list;
$t = time - $t0;

print "OK\n";
$qps = 65536/$t;

print "AAAA Performance was $qps q/s\n";

finish;
