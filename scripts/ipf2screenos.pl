#!/usr/bin/perl

# ipf2screenos - tdcdf1, part of the APM Suite of tools

# Initialise

use Data::Dumper;
use Getopt::Long;
use Net::Netmask;
use Parse::RecDescent;

use strict;

my ($debug, $help, $ipf, $untrust, $v6capable, %aobj, %pol, %usedpobj);

# Process options

my $go = GetOptions (
			"d"   => \$debug,
			"h"   => \$help,
			"u=s" => \$untrust,
			"6"   => \$v6capable,
);

if ($help) {
	print "\nUsage: cat <filename> | $0 -u <untrust_interface_name> [-6|d|h]\n";
	print "-6 = Assume you are dealing with ScreenOS with IPV6 support\n";
	print "-d = Enable debugging, appears inline with output\n";
	print "-h = This help\n\n";
	exit;
}
die "No untrusted interface! use -u=fxp0" unless ($untrust);

while (<STDIN>) {
	$ipf .= $_;
}
die "No input!" unless ($ipf);

my @ipf = split (/\n/, $ipf);

# pobj holds our policy object database, we'll seed this with screenos builtin objects such to reduce number of object creations in the conversion

my %pobj = (
        "AOL" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>5190, dstend=>5194, builtin=>1, },
        "APPLE-ICHAT-SNATMAP" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>5678, dstend=>5678, builtin=>1, },
        "BGP" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>179, dstend=>179, builtin=>1, },
        "CHARGEN" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>19, dstend=>19, builtin=>1, },
        "DHCP-Relay" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>67, dstend=>67, builtin=>1, },
        "DISCARD" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>9, dstend=>9, builtin=>1, }, 
        "DNS" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>53, dstend=>53, builtin=>1, }, 
        "ECHO" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>7, dstend=>7, builtin=>1, }, 
        "FINGER" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>79, dstend=>79, builtin=>1, },
        "FTP" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>21, dstend=>21, builtin=>1, },  
        "GNUTELLA" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>6346, dstend=>6347, builtin=>1, },
        "GOPHER" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>70, dstend=>70, builtin=>1, },
        "GTP" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>3386, dstend=>3386, builtin=>1, },
        "H.323" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>1720, dstend=>1720, builtin=>1, },
        "HTTP" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>80, dstend=>80, builtin=>1, },
        "HTTP-EXT" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>7001, dstend=>7001, builtin=>1, },
        "HTTPS" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>443, dstend=>443, builtin=>1, },
        "IDENT" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>113, dstend=>113, builtin=>1, }, 
        "IKE" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>500, dstend=>500, builtin=>1, },  
        "IMAP" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>143, dstend=>143, builtin=>1, },
        "IRC" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>6660, dstend=>6669, builtin=>1, }, 
        "L2TP" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>1701, dstend=>1701, builtin=>1, },
        "LDAP" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>389, dstend=>389, builtin=>1, }, 
        "LPR" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>515, dstend=>515, builtin=>1, },
        "MAIL" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>25, dstend=>25, builtin=>1, }, 
        "MGCP-CA" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>2727, dstend=>2727, builtin=>1, },
        "MGCP-UA" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>2427, dstend=>2427, builtin=>1, },
        "MS-RPC-EPM" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>135, dstend=>135, builtin=>1, },
        "MS-SQL" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>1433, dstend=>1433, builtin=>1, },
        "MSN" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>1863, dstend=>1863, builtin=>1, },
        "NBDS" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>138, dstend=>138, builtin=>1, }, 
        "NBNAME" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>137, dstend=>137, builtin=>1, },
        "NFS" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>111, dstend=>111, builtin=>1, },  
        "NNTP" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>119, dstend=>119, builtin=>1, },  
        "NSM" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>69, dstend=>69, builtin=>1, },  
        "NTP" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>123, dstend=>123, builtin=>1, },
        "NetMeeting" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>1720, dstend=>1720, builtin=>1, },
        "PC-Anywhere" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>5632, dstend=>5632, builtin=>1, },
        "POP3" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>110, dstend=>110, builtin=>1, },
        "PPTP" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>1723, dstend=>1723, builtin=>1, },
        "RADIUS" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>1812, dstend=>1813, builtin=>1, },
        "REXEC" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>512, dstend=>512, builtin=>1, }, 
        "RIP" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>520, dstend=>520, builtin=>1, }, 
        "RLOGIN" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>513, dstend=>513, builtin=>1, },
        "RSH" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>514, dstend=>514, builtin=>1, }, 
        "RTSP" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>554, dstend=>554, builtin=>1, }, 
        "SCCP" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>2000, dstend=>2000, builtin=>1, },
        "SIP" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>5060, dstend=>5060, builtin=>1, },
        "SMB" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>139, dstend=>139, builtin=>1, }, 
        "SMTP" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>25, dstend=>25, builtin=>1, }, 
        "SNMP" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>161, dstend=>161, builtin=>1, },
        "SSH" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>22, dstend=>22, builtin=>1, }, 
        "SUN-RPC-PORTMAPPER" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>111, dstend=>111, builtin=>1, },
        "SYSLOG" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>514, dstend=>514, builtin=>1, },
        "TALK" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>517, dstend=>518, builtin=>1, },
        "TELNET" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>23, dstend=>23, builtin=>1, },
        "TFTP" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>69, dstend=>69, builtin=>1, },
        "UUCP" => { proto => 'udp', srcstart=>0, srcend=>65535, dststart=>540, dstend=>540, builtin=>1, },
        "VNC" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>5800, dstend=>5800, builtin=>1, },
        "WAIS" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>210, dstend=>210, builtin=>1, },
        "WHOIS" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>43, dstend=>43, builtin=>1, },
        "WINFRAME" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>1494, dstend=>1494, builtin=>1, },
        "X-WINDOWS" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>6000, dstend=>6063, builtin=>1, },
        "YMSG" => { proto => 'tcp', srcstart=>0, srcend=>65535, dststart=>5050, dstend=>5050, builtin=>1, },
);

# Next, Program the Grammar for IPFILTER into our custom Parser

my %opmapper = (
			'<='	=> { 
					'start'	=>	0,
					'name'  =>      'LE',
					'inc'	=>	1,
				},
			'>='	=> {
					'end'	=>	65535,
					'name'	=>	'GE',
					'inc'	=>	1,
				},
			'<'	=> {	
					'start'	=>	0,
					'name'	=>	'LT',
					'inc'	=>	0,
				},
			'>'	=> {
					'end'	=>	65535,
					'name'	=>	'GT',
					'inc'	=>	0,
				},
);

my $ipfgrammar = q {

        <autotree>

	ipf	:	lnum ipftype ipfdir ipfmode ipfint ipfproto ipfsiptoke ipfdiptoke ipfstate
		|	lnum ipftype ipfdir ipfmode ipfint ipfsiptoke ipfdiptoke ipfstate
		|	lnum ipftype ipfdir ipfmode ipfint ipfproto ipfsiptoke ipfdiptoke
		|	lnum ipftype ipfdir ipfmode ipfint ipfsiptoke ipfdiptoke
		|	lnum ipftype ipfdir ipfmode ipfsiptoke ipfdiptoke

	lnum	:	/\@(\d+)/

        op      :       '='
                |       '!='
                |       '<='
                |       '>='
                |       '>'
                |       '<'

        compop  :       /(port)/ op port

        ipftype :       /(pass|block)/

	ipfdir  :	/(in|out)/
	
	ipfmode : 	/quick/
		|	/log quick/

	ipfint	:	/on/ int

	ipfproto : 	/proto/ proto

	ipfstate : 	/(keep state)/

        port    :       /([a-z0-9\-]+)/

        proto   :       /([a-z0-9]+)/

        int   	:       /([a-z0-9]+)/

        port    :       /([a-z0-9\-]+)/

	ipanyaddr :      "any"

        ipv4addr:       ch32
                |       ipanyaddr

        ipv6addr:       ch128
                |       ipanyaddr

        iptoke:         ipv4addr compop
                |       ipv4addr
                |       ipv6addr compop
                |       ipv6addr

        ipfsiptoke :	/from/ iptoke

        ipfdiptoke :    /to/ iptoke

        ch32	:       /(\d+\.\d+\.\d+\.\d+\/\d+)/

        ch128	:       /([0-9a-fA-F:\/])+/

};

# Parse

my $ipfparser = Parse::RecDescent->new($ipfgrammar);

my %created;
foreach (@ipf) {
	my $result = $ipfparser->ipf($_);
	if ($result) {
		my $lnum 	= $result->{'lnum'}->{'__VALUE__'};
		my $ipftype 	= $result->{'ipftype'}->{'__VALUE__'};
		my $ipfint 	= $result->{'ipfint'}->{'int'}->{'__VALUE__'};
		my $ipfdir 	= $result->{'ipfdir'}->{'__VALUE__'};
		my $ipfstate 	= $result->{'ipfstate'}->{'__VALUE__'};
		my $options 	= $result->{'ipfmode'}->{'__VALUE__'};

		my $mode 	= ($ipftype eq 'pass') 			? 'permit' : 'deny';
		my $fromzone 	= ($ipfint && $ipfint ne $untrust) 	? 'trust'  : 'untrust';
		my $tozone	= ($fromzone eq 'untrust') 		? 'trust'  : 'untrust';

		my $ipfsiptoke 	= $result->{'ipfsiptoke'}->{'iptoke'} if ($result->{'ipfsiptoke'}->{'iptoke'});
		my $ipfdiptoke 	= $result->{'ipfdiptoke'}->{'iptoke'} if ($result->{'ipfdiptoke'}->{'iptoke'});

		my $proto 	= $result->{'ipfproto'}->{'proto'}->{'__VALUE__'} if ($result->{'ipfproto'}->{'proto'}->{'__VALUE__'});

		my ($src, $dst, $sop, $sport, $dop, $dport, $spname, $dpname);

		if ($ipfsiptoke) {
			if    ($ipfsiptoke->{'ipv4addr'}) {
				if ($ipfsiptoke->{'ipv4addr'}->{'ipanyaddr'}) {	
					$src = ($v6capable) ? 'Any-IPv4' : 'any';
				}
				elsif ($ipfsiptoke->{'ipv4addr'}->{'ch32'}) {
					$src = $ipfsiptoke->{'ipv4addr'}->{'ch32'}->{'__VALUE__'};
					$aobj{$fromzone}->{$src} = $src;
					
				}
			}
			elsif ($ipfsiptoke->{'ipv6addr'}) {
				if ($ipfsiptoke->{'ipv6addr'}->{'ipanyaddr'}) {	
					$src = 'Any-IPv6';
				}
				elsif ($ipfsiptoke->{'ipv6addr'}->{'ch128'}) {
					$src = $ipfsiptoke->{'ipv6addr'}->{'ch128'}->{'__VALUE__'};
					$aobj{$fromzone}->{$src} = $src;
				}
			}

			$pol{$lnum}->{'src'} = $src;

			if   ($ipfsiptoke->{'compop'}) {
				$sop   = $ipfsiptoke->{'compop'}->{'op'}->{'__VALUE__'};
				$sport = $ipfsiptoke->{'compop'}->{'port'}->{'__VALUE__'};
			}
		}
		if ($ipfdiptoke) {
			if    ($ipfdiptoke->{'ipv4addr'}) {
				if ($ipfdiptoke->{'ipv4addr'}->{'ipanyaddr'}) {	
					$dst = ($v6capable) ? 'Any-IPv4' : 'any';
				}
				elsif ($ipfdiptoke->{'ipv4addr'}->{'ch32'}) {
					$dst = $ipfdiptoke->{'ipv4addr'}->{'ch32'}->{'__VALUE__'};
					$aobj{$tozone}->{$dst} = $dst;
				}
			}
			elsif ($ipfdiptoke->{'ipv6addr'}) {
				if ($ipfdiptoke->{'ipv6addr'}->{'ipanyaddr'}) {	
					$dst = 'Any-IPv6';
				}
				elsif ($ipfdiptoke->{'ipv6addr'}->{'ch128'}) {
					$dst = $ipfdiptoke->{'ipv6addr'}->{'ch128'}->{'__VALUE__'};
					$aobj{$tozone}->{$dst} = $dst;
				}
			}

			$pol{$lnum}->{'dst'} = $dst;

			if   ($ipfdiptoke->{'compop'}) {
				$dop   = $ipfdiptoke->{'compop'}->{'op'}->{'__VALUE__'};
				$dport = $ipfdiptoke->{'compop'}->{'port'}->{'__VALUE__'};
			}
		}

		if ($proto=~m/tcp|udp/i) {
			$pol{$lnum}->{'proto'} eq uc($proto);

			if ($sop && $sport) {

				if ($sop eq '=' || $sop eq '!=') {
					$mode eq 'deny' if ($sop eq '!=');	# Flip mode to deny if ipf negation
					$spname = uc(getservbyport($sport, $proto)) || uc($proto) . "_$sport";
					$pobj{$spname}{'proto'}=$proto;
					$pobj{$spname}{'srcstart'}=$sport;
					$pobj{$spname}{'srcend'}=$sport;
				}
				else {
					$spname = uc($proto) . '_' . $opmapper{$sop}->{'name'} . '_' . $sport;
					$pobj{$spname}{'proto'}=$proto;
					if ($opmapper{$sop}->{'start'}) {
						$pobj{$spname}{'srcstart'} = $opmapper{$sop}->{'start'};
					}
					else {
						$pobj{$spname}{'srcstart'} = $sport += $opmapper{$sop}->{'inc'};
					}
					if ($opmapper{$sop}->{'end'}) {
						$pobj{$spname}{'srcend'} = $opmapper{$sop}->{'end'};
					}
					else {
						$pobj{$spname}{'srcend'} = $sport += $opmapper{$sop}->{'inc'};
					}
				}

			}
			if ($dop && $dport) {

				if ($dop eq '=' || $dop eq '!=') {
					$mode eq 'deny' if ($dop eq '!=');	# Flip mode to deny if ipf negation
					$dpname = uc(getservbyport($dport, $proto)) || uc($proto) . "_$dport";
					$pobj{$dpname}{'proto'}=$proto;
					$pobj{$dpname}{'dststart'}=$dport;
					$pobj{$dpname}{'dstend'}=$dport;
				}
				else {
					$dpname = uc($proto) . '_' . $opmapper{$dop}->{'name'} . '_' . $dport;
					$pobj{$dpname}{'proto'}=$proto;
					if ($opmapper{$dop}->{'start'}) {
						$pobj{$dpname}{'dststart'} = $opmapper{$dop}->{'start'};
					}
					else {
						$pobj{$dpname}{'dststart'} = $dport += $opmapper{$dop}->{'inc'};
					}
					if ($opmapper{$dop}->{'end'}) {
						$pobj{$dpname}{'dstend'} = $opmapper{$dop}->{'end'};
					}
					else {
						$pobj{$dpname}{'dstend'} = $dport += $opmapper{$dop}->{'inc'};
					}
				}

			}

			if ($spname && $dpname) {	# Conjoined, complex protocol definition
				my $pname = $spname . '_' . $dpname;
				$pobj{$pname}{'proto'} = $pobj{$spname}{'proto'};
				$pobj{$pname}{'srcstart'} = $pobj{$spname}{'srcstart'};
				$pobj{$pname}{'srcend'} = $pobj{$spname}{'srcend'};
				$pobj{$pname}{'dststart'} = $pobj{$dpname}{'dststart'};
				$pobj{$pname}{'dstend'} = $pobj{$dpname}{'dstend'};
				$pol{$lnum}->{'port'} = $pname;
			}
			elsif ($spname) {
				$pobj{$spname}{'dststart'}=0;
				$pobj{$spname}{'dstend'}=65535;
				$pol{$lnum}->{'port'} = $spname;
			}
			elsif ($dpname) {
				$pobj{$dpname}{'srcstart'}=0;
				$pobj{$dpname}{'srcend'}=65535;
				$pol{$lnum}->{'port'} = $dpname;
			}
			else {
				$pol{$lnum}->{'port'} = uc($proto) . '-' . "ANY";
			}

		}
		elsif ($proto eq 'icmp') {
			$pol{$lnum}->{'proto'} = 'icmp';
			$pol{$lnum}->{'port'} = 'ICMP-ANY';
		}
		elsif ($proto) {
			$pol{$lnum}->{'proto'} = $proto;
			$pol{$lnum}->{'port'} = uc($proto);
		}
		else {
			$pol{$lnum}->{'proto'} = 'any';
			$pol{$lnum}->{'port'} = 'any';
		}

		#warn "No port in $lnum for proto $pol{$lnum}->{'proto'}" unless ($pol{$lnum}->{'port'});

		$pol{$lnum}->{'mode'} = $mode;
		$pol{$lnum}->{'fromzone'} = $fromzone;
		$pol{$lnum}->{'tozone'} = $tozone;
		$pol{$lnum}->{'oline'} = $_;
		$pol{$lnum}->{'log'} = ($options=~m/log/i) ? 'log' : '';
	}
	else {
		warn "Error parsing line: $_ , this line will be ignored\n";
	}
}

# Next, prune pobj for unused objects

foreach my $plnum (sort keys %pol) {
	$usedpobj{$pol{$plnum}->{'port'}} = $pol{$plnum}->{'oline'};
}
foreach my $pname (sort keys %pobj) {
	delete $pobj{$pname} unless $usedpobj{$pname};
}

# Now, ready to output, first create aobj

$Data::Dumper::Indent = 0;	# Set dump indent to 0 (no newlines) from default (2), so we can use for inline debug

foreach my $zone (sort keys %aobj) {
	foreach my $obj (sort keys %{$aobj{$zone}}) {
		my $addr = $obj;
		if ($addr !~m/:/) {
			my $nnm = Net::Netmask->new($addr);
			$addr = $nnm->base() . ' ' . $nnm->mask();
		}
		print "set address \"$zone\" \"$obj\" $addr\n";
	}
}

# Next, pobj

foreach my $pname (sort keys %pobj) {
	next if $pobj{$pname}{'builtin'};
	print "set service \"$pname\" protocol " . 
	$pobj{$pname}{'proto'} . 
	' ' .
	$pobj{$pname}{'srcstart'} . 
	'-' .
	$pobj{$pname}{'srcend'} . 
	' dst-port ' .
	$pobj{$pname}{'dststart'} . 
	'-' .
	$pobj{$pname}{'dstend'};
	print ' (' . Dumper($pobj{$pname}) . ')' if ($debug);
	print "\n";
	
}

# Finally, pol

foreach my $plnum (sort keys %pol) {
	print 'set policy ' . 
	'from "' . 
	$pol{$plnum}->{'fromzone'} . 
	'" to "' . 
	$pol{$plnum}->{'tozone'} . 
	'" "' . 
	$pol{$plnum}->{'src'} . 
	'" "' . 
	$pol{$plnum}->{'dst'} . 
	'" "' . 
	$pol{$plnum}->{'port'} . 
	'" ' . 
	$pol{$plnum}->{'mode'} .
	' ' .
	$pol{$plnum}->{'log'};
	print " ($pol{$plnum}->{'oline'}) " if ($debug);
	print "\n";
}


