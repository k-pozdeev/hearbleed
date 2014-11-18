#! /bin/usr/perl
# Perl Class MySSL provides an object and some routines to talk via SSL/TLS connection.
# Connects to specified host:port and sends TLS requests: ClientHello, Heartbeat (only this currently supported).
# Parses response and provides information
# Based on script https://github.com/noxxi/p5-scripts/blob/master/check-ssl-heartbleed.pl

# Overview

# Objects:
#   $myssl = MySSL->new() - an object to operate with.

# Methods:
#   $myssl->protocolVersion([$mayor, $minor]) - sets or shows currently set ssl version.

#   $myssl->ciphers([@ciphers]) - sets or returns array of ciphers to send to server in TLS request.
#   $myssl->getOpenSSLCiphers($sslVersion) - returns array of ciphers provided by OpenSSL library according to chosen version of SSL.
   
#   $myssl->connect($host, $port) - connects to peer.
#   $myssl->close() - closes socket.

#   $myssl->getResponse() - gets a response from peer.
#   $myssl->clientHello() - sends clientHello.

package MySSL;

use IO::Socket::INET;
use Net::SSLeay;
use Switch;

#TODO: delete debugString

sub debugString {
  my $s = @_[0];
  print map(ord($_)." ", split(//, $s));
  #foreach $one (split(//, $s)) {
  #  print ord($one)." ";
  #}
  print "\n\n";
}

sub new {
  my $class = shift;
  my $self = {
#TODO решить, нужны ли эти поля
    ciphers => '',
    protocolVersion => '',
    socket => '',
  };
  bless $self, $class;
  return $self;
}

sub protocolVersion {
# usage: protocolVersion([$mayor, $minor])
# sets version of protocol or returns what was set
  my $self = shift;
  return $self->{protocolVersion} if !@_;
  $self->{protocolVersion} = [$_[0], $_[1]];
}

sub ciphers {
# usage: ciphers([\@ciphersArray])
  my $self = shift;
  return $self->{ciphers} if !@_;
  $self->{ciphers} = $_[0];
}

sub getOpenSSLCiphers {
# usage: getOpenSSLCiphers('ssl2|ssl3|tls1')
# returns array of ciphers or false if not found
  my $self = shift;
  if (!defined $_[0]) { return 0; }
  if ($_[0] !~ /ssl2|ssl3|tls1/) { return 0; }
  my $temp = `openssl ciphers -V -$_[0]`;
  my @ciphers = ();
  while ($temp =~ /(0x[0-9A-F]{2})/g) { push @ciphers, hex($1); }
  return \@ciphers;
}

sub connect {
# usage: connect($host, $port)
  my $self = shift;
  if (!defined $_[0] || !defined $_[1]) { return 0; }
  $self->{socket} = IO::Socket::INET->new (
    PeerAddr => $_[0],
    PeerPort => $_[1],
    Type => SOCK_STREAM
  ) or die "Failed to connect: $!";
}

sub close {
  my $self = shift;
  $self->{socket}->close;
}

sub clientHello {
  my $self = shift;
  randomize;
  my $protocolVersion = ($self->{protocolVersion}[0] << 8) + $self->{protocolVersion}[1];
  my $random = pack("N C28", time(), (map(int(rand(256)), (1..28))));
  my $compressionMethod = "\0";
  my $ext = '';
  my $clientHello = pack("n a32 C n/a C/a n/a", $protocolVersion, $random, length($self->{sessionID}), pack("C*", @{$self->{ciphers}}), $compressionMethod, $ext);
  #debugString($clientHello);
  #Prepare Handshake data
  my $handshake = pack("C a*", 1, substr(pack("N/a", $clientHello), 1));
  #Prepare TlsPlainText
  my $TLSPlainText = pack("C n n/a", 22, $protocolVersion, $handshake);
  $self->{socket}->send($TLSPlainText);
}

sub heartbeat {
# usage: heartbeat($length [, $data])
# Sends heartbeat. If $data not defined, sends random data with length $length
# Data may have length not equal to $length for testing purposes
  my $self = shift;
  die "no argument" if !@_;
  (my $length, my $data) = @_;
  if (!defined $data) {
    $data = '';
    for (my $x = 0; $x < $length; $x++) { $data .= chr(int(rand(254) + 1)); }
  }
  my $padding = '';
  if ($length == length($data)) {
    for ($x = 0; $x < 20; $x++) { $padding .= chr(int(rand(254) + 1)); }
  }
  my $protocolVersion = ($self->{protocolVersion}[0] << 8) + $self->{protocolVersion}[1];
  my $heartbeatMessage = pack("C n a*", 1, $length, $data.$padding);
  my $TLSPlainText = pack("C n n/a", 24, $protocolVersion, $heartbeatMessage);
  $self->{socket}->send($TLSPlainText);
}

sub getResponse {
# usage: getResponse(\$buf)
# Places server response to $buf after you have sent request
# Returns 0 if timeout, undef if error, see $! then.
  my $self = shift;
  die "no argument" if !@_;
  my $buf = shift;
  my $rin = '';
  vec($rin, fileno($self->{socket}), 1) = 1;
  if (!select($rin, undef, undef, 5)) { return 0; }
	$$buf = '';
	my $len = 100;
	while (1) {
		$bytesRead = sysread($self->{socket}, $$buf, $len, length($$buf));
		if (!defined $bytesRead) { return undef; }
		if ($bytesRead < $len) { return length($$buf); }
	}
}

#TODO распарсить весь респонс, выдачу сунуть в массив хешей
sub parseTLSPlaintext {
  my $self = shift;
  die "no argument" if !@_;
  my $input = shift;
  my @output = ();
  while (length($input)) {
	  (my $contentType, my $mayor, my $minor, my $raw) = unpack('C C C n/a', $input);
	  $input = substr($input, 5 + length($raw));
	  my $temp = {
	    contentType => $contentType,
	    protocolVersion => [$mayor, $minor],
	    #raw => $raw,
	  };
	  switch ($contentType) {
	    case 22 { $self->parseHandshake($temp, $raw); }
      case 24 { $self->parseHeartbeat($temp, $raw); }
	    else { die "Unsupported contentType: $contentType"; }
	  }
	  push @output, $temp;
	}
  return \@output;
}

#TODO определиться, возвращать ошибку или убивать скрипт
#TODO определиться, передавать изменяемые данные по ссылке или возвращать из подпрограммы

sub parseHandshake {
  my $self = shift;
  die "no argument" if !@_;
  (my $output, my $input) = @_;
	$input = substr($input, 0, 1).chr(0).substr($input, 1);
  (my $handshakeType, my $raw) = unpack('C N/a', $input);
  $output->{handshake} = {
  	handshakeType => $handshakeType,
  	#raw => $raw,
  };
  switch ($handshakeType) {
    case 2 { $self->parseServerHello($output->{handshake}, $raw); }
    case 11 { $self->parseCertificate($output->{handshake}, $raw); }
    case 14 { $output->{handshake}->{serverHelloDone} = {} }
    else {
    	my $temp = '';
    	map($temp .= ord($_)." ", split(//, $raw));
    	$output->{handshake}->{unsupportedHandshakeType} = {
    		raw => $raw,
    		numeric => $temp,
    	}
  	}
  }
}

sub parseServerHello {
  my $self = shift;
  die "no argument" if !@_;
  (my $output, my $input) = @_;
  (my $mayor, my $minor, my $time, my $random, my $sessionID, my $cipherSuite, my $compressionMethod) = unpack('C C N a28 C/a n C', $input);
  $output->{serverHello} = {
    protocolVersion => [$mayor, $minor],
    time => $time,
    random => $random,
    sessionID => $sessionID,
    cipherSuite => [$cipherSuite >> 8, $cipherSuite % 256],
    compressionMethod => $compressionMethod,
  };
}

sub parseCertificate {
  my $self = shift;
  die "no argument" if !@_;
  (my $output, my $input) = @_;
  my $totalLength = unpack("N", "\0$input");
  $input = substr($input, 3);
  #die "Error while parsing certificate" if length($input) != $totalLength;
  my @certs = ();
  while (length($input) > 3) {
  	my $length = unpack("N", "\0$input");
  	$input = substr($input, 3);
  	#die if length($input) < $length;
  	my $cert = substr($input, 0, $length, '');
  	push @certs, cert2line($cert);
  }
  $output->{certificates} = \@certs;
}

sub parseHeartbeat {
  my $self = shift;
  die "no argument" if !@_;
  (my $output, my $input) = @_;
  (my $heartbeatMessageType, my $payload) = unpack("C N/a", $input);
  $output->{heartbeat} = {
    heartbeatMessageType => $heartbeatMessageType,
    payload => $payload,
  };
}

sub cert2line {
    my $der = shift;
    my $bio = Net::SSLeay::BIO_new( Net::SSLeay::BIO_s_mem());
    Net::SSLeay::BIO_write($bio,$der);
    my $cert = Net::SSLeay::d2i_X509_bio($bio);
    Net::SSLeay::BIO_free($bio);
    $cert or die "cannot parse certificate: ".
Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
    my $not_before = Net::SSLeay::X509_get_notBefore($cert);
    my $not_after = Net::SSLeay::X509_get_notAfter($cert);
    $_ = Net::SSLeay::P_ASN1_TIME_put2string($_) for($not_before,$not_after);
    my $subject = Net::SSLeay::X509_NAME_oneline(
Net::SSLeay::X509_get_subject_name($cert));
    return "$subject | $not_before - $not_after";
}

1;
#TODO дописать описание вверху файла
