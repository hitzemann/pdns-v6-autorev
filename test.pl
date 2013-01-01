use Modern::Perl;
use autodie qw( :all );
use IPC::Open3;
use Symbol 'gensym'; 
use Benchmark::Timer;

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

#speak "Q\t4.a.9.7.b.9.e.f.0.0.0.0.0.0.0.0.f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa\tIN\tANY\t-1\t127.0.0.1\t127.0.0.1\t127.0.0.1";
#result "Reverse ",expect "DATA\t0\t1\t4.a.9.7.b.9.e.f.0.0.0.0.0.0.0.0.f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa\tIN\tPTR\t300\t-1\tnode-h6tn42i.dyn.test";
#expect "END";
#speak "Q\tnode-h6tn42i.dyn.test\tIN\tANY\t-1\t127.0.0.1\t127.0.0.1\t127.0.0.1";
#result "Forward ",expect "DATA\t0\t1\tnode-h6tn42i.dyn.test\tIN\tAAAA\t300\t-1\tfe80:0000:0250:56ff:0000:0000:fe9b:79a4";
#expect "END";

my @list;

map {
push @list, (join '.', split //, sprintf("%04x",$_));
} (0 .. 0xffff);

# speed test
print "Testing speed for PTRs (this will take some time)";
my $t1 = Benchmark::Timer->new(skip => 100, confidence => 97.5, error => 2, minimum => 2000);
while ($t1->need_more_samples('ptr')) {
    my $val = pop @list;
    $t1->start('ptr');
    print $wr "Q\t$val.b.9.e.f.0.0.0.0.0.0.0.0.f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa\tIN\tANY\t-1\t127.0.0.1\t127.0.0.1\t127.0.0.1\n";
    my $scrap = <$rd>;
    $t1->stop('ptr');
    $scrap = <$rd>;
}

print "OK, ";
say "qps: ".1/$t1->result('ptr');
say $t1->report;

@list = [];
open(NOD, '<nodes.txt');
while (my $line = <NOD>) {
    chomp $line;
    push @list, $line;
}
close(NOD);
shift @list;

print "Testing speed for AAAAs (this will take some time)";
my $t2 = Benchmark::Timer->new(skip => 100, confidence => 97.5, error => 2, minimum => 2000);
while ($t2->need_more_samples('aaaa')) {
    my $val = pop @list;
    $t2->start('aaaa');
    print $wr "Q\tnode-$val.dyn.test\tIN\tANY\t-1\t127.0.0.1\t127.0.0.1\t127.0.0.1\n";
    my $scrap = <$rd>;
    $t2->stop('aaaa');
    $scrap = <$rd>;
}

print "OK, ";
say "qps: ".1/$t2->result('aaaa');
say $t2->report;

finish;
