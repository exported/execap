#!/usr/bin/perl

use strict;
use warnings;

use Net::RawIP;

# This program reads in an EXE and sends it over the network in a random order
# in an attempt to test the tcp stream re-assembly code. 
# This script can be used as a starting point for other scripts that
# need to make use of a raw socket.


my $SIP = '132.239.181.229';
my $SPORT = 12345;
my $DIP = '132.239.1.114';
my $DPORT = 80;

my $MTU = 1400;

unless ((defined $ARGV[0]) && ($ARGV[0] =~ m/^\d+$/)) {
    die 'Please specify base seq as first parameter.', "\n";
}
my $BASE_SEQ = $ARGV[0];

unless ((defined $ARGV[1]) && (-e $ARGV[1])) {
    die 'Please specify file as second parameter.', "\n";
}

my $exe;
open (IN, $ARGV[1]) or die 'Unable to open file: ', $!, "\n";
{
    local $/ = undef;
    $exe  = <IN>;
}
close IN;

my $EXELEN = length $exe;

#my $EXELEN = 4000;
#$exe = '0123456789' x 400;


while (1) {

    my $thisseq = int((rand() * ($EXELEN + $MTU)) - ($MTU));
    my $thislen = int((rand() * ($MTU - 1)) + 1);

    if ($thisseq < 0) {
	$thisseq = 0;
    }

    if ($thisseq + $thislen >= $EXELEN) {
	$thisseq -= (($thisseq + $thislen) - $EXELEN);
    }

    raw_send($SIP, $SPORT, $DIP, $DPORT, $BASE_SEQ, $thisseq,
	     substr($exe, $thisseq, $thislen));

    select(undef, undef, undef, 0.1);
}


sub raw_send {
    my ($src_ip, $src_port, $dst_ip, $dst_port, $base_seq, $seq, $data) = @_;

    my $packet = new Net::RawIP;

    $packet->set({'ip'=>{'saddr' => $src_ip,
			 'daddr' => $dst_ip},
		  'tcp'=>{'source'=>$src_port,
			  'dest'=>$dst_port,
			  'ack'=>1,
			  'syn'=>0,
			  'seq'=>($base_seq + $seq) & 0xFFFFFFFF,
			  'ack_seq'=>1,
			  'data'=>$data}
		 });
    
    $packet->send(0,1);
}


