use Modern::Perl;
use autodie;
use Test::More tests => 10;
use IPC::Open3;
use Symbol 'gensym';

my ($wr, $rd, $err);
$err = gensym;
my $pid;
$pid = open3($wr, $rd, $err, './rev.pl') or fail("open rev.pl");
pass("open rev.pl");

print $wr "HELO\t3\n";
my $read = <$rd>;
like ($read, qr/^OK.*/, 'Starting API version 3');

print $wr "Q\t4.a.9.7.b.9.e.f.0.0.0.0.0.0.0.0.f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa\tIN\tANY\t-1\t127.0.0.1\t127.0.0.1\t127.0.0.1\n";
$read = <$rd>;
chomp $read;
is ($read, "DATA\t0\t1\t4.a.9.7.b.9.e.f.0.0.0.0.0.0.0.0.f.f.6.5.0.5.2.0.0.0.0.0.0.8.e.f.ip6.arpa\tIN\tPTR\t300\t-1\tnode-h6tn42i.dyn.test", "PTR records");
$read = <$rd>;
chomp $read;
is ($read, "END", "PTR answer terminator");

print $wr "Q\tnode-h6tn42i.dyn.test\tIN\tANY\t-1\t127.0.0.1\t127.0.0.1\t127.0.0.1\n";
$read = <$rd>;
chomp $read;
is ($read, "DATA\t0\t1\tnode-h6tn42i.dyn.test\tIN\tAAAA\t300\t-1\tfe80:0000:0250:56ff:0000:0000:fe9b:79a4", "AAAA records");
$read = <$rd>;
chomp $read;
is ($read, "END", "AAAA answer terminator");

print $wr "PING\t1\n";
$read = <$rd>;
chomp $read;
is ($read, "END", "PING reply");

print $wr "AXFR\t42534\n";
$read = <$rd>;
chomp $read;
is ($read, "END", "AXFR reply");

print $wr "FOO\tBAR\n";
$read = <$rd>;
chomp $read;
is ($read, "FAIL\tUnsupported request", "Illegal Request");
$read = <$rd>;
chomp $read;
is ($read, "END", "Illegal Request terminator");
