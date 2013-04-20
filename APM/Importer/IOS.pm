#!/usr/bin/perl
#


package APM::Importer::IOS;

use APM;
use APM::DBI;
use Net::Netmask;
use strict;
use Carp;
use Readonly;
use Data::Dumper;
use Scalar::Util 'blessed';
use Parse::RecDescent;
use Smart::Comments;


=pod

=head1 NAME

        APM::Importer::IOS

=head1 ABSTRACT

        Class to implement an Access Policy Manager Policy Importer for IOS

=head1 SYNOPSIS

	use APM;
        use APM::Importer;

        #################
        # class methods #
        #################
        $apmAppHandler    = APM::Importer::IOS->new     (                               #Initialise class

                                                debug => [0|1|2],       #Debug can be switched on, 1 is standard, 2 is with callstack
                                        	debugfile => $filename, #Debug can be sent to a file instead of STDOUT
                                        	debugstream => [0|1]    #Debug can be mirrored to a stream as well
                                                                	#Call getDebugStream to retrieve

						dbi => APM::DBI		#APM DBI object if you dont want to open a new DB connection

                                );


        #######################
        # object data methods #
        #######################

				parseConfig				#Parse configuration but do NOT apply any applications
									#This method only to be used by the importer

	######################
	# object properties  #
	######################


=head1 DESCRIPTION


We advise you to perform imports using the APM interface (importConfig)


=head1 TODO

        Tidy POD

=cut

my %cache;		#General all purpose cache
my $dbi;
my $types;
my $typesbyid;
my $icmpgrammar;


sub new
{
 my $proto = shift;
 my $class = ref $proto || $proto;

 my $this = { };
	
 bless($this, $class);

 #Process instantuation arguments
    if (@_ > 1) {
      my %args = @_;
      foreach (keys %args) {
	 my $argname = lc("in_$_");
         $this->{$argname}=$args{$_};
      }
   }


 if ($this->{in_debug}) {
	$this->{_debug} = ($this->{in_debug});
 }
 if ($this->{in_debugfile}) {
	$this->{_debugfile} = ($this->{in_debugfile});
 }
 if ($this->{in_debugstream}) {
	$this->{_debugstream} = ($this->{in_debugstream});
 }

 $this->_debug("Initialising $class...");

 if ($this->{in_dbi}) {
	if ((blessed ($this->{in_dbi})) && $this->{in_dbi}->isa('APM::DBI')) {
		$this->_debug("We were passed a valid APM::DBI object, using it...");
		$dbi = $this->{in_dbi};
	}
	else {
		croak "$class requires a valid APM::DBI object to be passed";
	}
 }
 else {
 	#Initialise the DBI connection ourselves
	$this->_debug("We were NOT passed a valid APM::DBI object, constructing one...");
 	$dbi = APM::DBI->new(
				debug		=>	$this->{_debug},
				debugstream	=>	$this->{_debugstream},
				debugfile	=>	$this->{_debugfile},
			) || croak "$class could not construct an APM::DBI object ourselves";
 }

 $types = $dbi->{types};
 $typesbyid = $dbi->{typesbyid};

 #Clean out all the input fields
 foreach my $inkey (sort keys %{$this}) {
	if ($inkey=~m/^in_/) {
		delete $this->{$inkey};
	}
 };

 #Get a new APM worker
 $this->{apm} = APM->new();

 return $this;

}

#Debug

sub _debug {
        my $self = shift;
        my $msg = shift;
        return unless ($self->{'_debug'});

        #Identify caller
        if ($self->{'_debug'} == 2) {   #Callstack debug

                my $maxcalldepth = 8;   #Maximum call depth we will trace to
                my $calls;              #Iterator
                my $callstack;          #Call stack
                my $tabstack;           #Tab stack
                for ($calls = $maxcalldepth; $calls > 0; $calls--) {
                        my $stackptr = (caller($calls))[3];
                        $callstack.="$stackptr\/" if ($stackptr);
                }; chop($callstack);
                $msg = "$callstack(): $msg";

        }
        else {                          #Standard caller debug
                my $caller = (caller(1))[3] || (caller(0))[3];
                $msg = "$caller(): $msg";
        }

        if ($self->{'_debugfile'}) {
                open (DEBUGFILE, ">>$self->{'_debugfile'}") || return;
                print DEBUGFILE "$msg\n";
                close (DEBUGFILE);
        }
        else {
                if ($self->{'_debugstream'}) {
                        $self->{'_debug_stream'} .= "$msg\n";
                }
                else {
                        print STDERR "$msg\n";
                }
        }
        return;
}

sub parseConfig {

	my $self = shift;

	my $config = shift;

        croak "Internal error: no config specified!" unless ($config);

	$self->_debug("IOS Parser starting....");
	$self->_debug("Populating ICMP cache....");
	$self->_popicmpcache;

	my @config = split (/\n/,$config);

	my $aclgrammar = q {

		<autotree>
		{ my ($iaclname,$iacltype,@retarr); }

	        acl     :       /^\s*access-list (\d{1,2})/ acltype oldipv4addr
			{ $iaclname = $1; $iacltype='legacy'; @retarr = ($iaclname,$iacltype,\%item); $return=\@retarr; }
	                |       /^\s*access-list (\d{2,3})/ extacltype siptoke diptoke
			{ $iaclname = $1; $iacltype='legacy'; @retarr = ($iaclname,$iacltype,\%item); $return=\@retarr; }
			|	seqno(?) extacltype siptoke diptoke
			{ $iaclname = 'none';$iacltype='new'; @retarr = ($iaclname,$iacltype,\%item); $return=\@retarr; }
			|	remark
			{ $iaclname = 'none';$iacltype='new'; @retarr = ($iaclname,$iacltype,\%item); $return=\@retarr; }

	
	        dd32    :       /(\d+\.\d+\.\d+\.\d+)/

		hdd32	:	dd32

		mdd32	:	dd32

		op	:	'eq'
			|	'neq'
			|	'lt'
			|	'gt'
	
	        compop  :       op port
			|	icmpcodetype

		icmpcodetype:	/(ICMPGRAMMAR)/		#This is a placeholder for an injected string of grammar

	        rangeop :       'range' sport dport

	        acltype :       /(permit|deny)/
	
	        extacltype:     acltype proto

		proto	:	/([a-z0-9]+)/

		port	:	/([a-z0-9\-]+)/

		sport	:	port

		dport	:	port

		seqno	:	/sequence (\d+)/

		detail	:	/(.*)/

		remark  :	/remark (.*)/

	        ipv4hostaddr:   "host" dd32
	
	        ipv4maskaddr:   hdd32 mdd32
	
	        ipanyaddr:    	"any"
	
	        oldipv4addr	:    hdd32 mdd32
	                	|    dd32
				|    ipanyaddr
	
	        ipv4addr:       ipv4hostaddr
	                |       ipv4maskaddr
	                |       ipanyaddr

	        iptoke:       	ipv4addr compop
	                |       ipv4addr rangeop
	                |       ipv4addr
			|	ipv6addr compop
			|	ipv6addr rangeop
			|	ipv6addr

		siptoke:	iptoke

		diptoke	:	iptoke detail
			|	iptoke

		ch128:		/([0-9a-fA-F:\/])+/

		ipv6addr:	ch128
			|	ipanyaddr


	
	};

	$aclgrammar =~ s/ICMPGRAMMAR/$icmpgrammar/;	#Inject ICMP Grammar
	
	my $aclparser = Parse::RecDescent->new($aclgrammar);

	#$::RD_TRACE = 1;	#Parse tracer, do NOT turn on unless you are SURE you know what you are doing , produces output++++
	
	my %acldb;
	my %objectdb;
	my %poldb;
	my %appdb;
	my %acl2app;
	my %numacls;
	my $eaclname;
	my $hostname;
	my $inint;
	my $ipv6;

	#First run through the configuration, extract the interesting bits and store in hashtables
	foreach (@config) {	### Parsing Configuration===[%]
	
		my ($result,$logging);

		#Skip lines which we don't care about
		next unless ($_=~m/access-list|permit|deny|remark|^hostname|^interface|ip access-group|ipv6 traffic-filter|^line \S+|access-class/);

		if ($_=~m/(.*) log$/	)   {	$logging = 'log'	; 	$_=$1; 	};
		if ($_=~m/(.*) log-input$/) {	$logging = 'log-input'	;	$_=$1;  };

		if ($_=~m/^hostname (.*)$/) {
			$hostname = $1;
			$result = 'NOPARSE';
		}
		elsif ($_=~m/^interface (.*)$/) {
			$inint = $1;
			$result = 'NOPARSE';
		}
		elsif ($_=~m/^line (.*)$/) {
			$inint = $_;
			$result = 'NOPARSE';
		}
		elsif (($_=~m/access-class (\S+) (in|out)/) && ($inint)) {
			if ($1=~m/^(\d+)$/) {
				$self->_debug("Found numeric access-class ($1) on $inint, not adding to appdb");
				push (@{$numacls{$1}{'line'}},$inint);
			}
			else {
				$self->_debug("Found alpha access-class ($1) on $inint, adding to appdb");
				$appdb{$inint}{'access-class'}{$2} = $1;
			}
			$result = 'NOPARSE';
		}
		elsif (($_=~m/ip access-group (\S+) (in|out)/) && ($inint)) {
			$appdb{$inint}{'access-group'}{$2} = $1;
			if ($1=~m/^(\d+)$/) {
				push (@{$numacls{$1}{'int'}},$inint);
			}
			$result = 'NOPARSE';
		}
		elsif (($_=~m/ipv6 traffic-filter (\S+) (in|out)/) && ($inint)) {
			$appdb{$inint}{'traffic-filter'}{$2} = $1;
			$result = 'NOPARSE';
		}
		elsif ($_=~m/^ip access-list (standard|extended) (\S+)$/) {
			$eaclname = $2;
			undef ($ipv6);
			next;
		}
		elsif ($_=~m/^access-list \d+/) {
			$result = $aclparser->acl($_);
			undef ($ipv6);
			undef ($eaclname);
		}
		elsif ($_=~m/^ipv6 access-list (\S+)$/) {
			$eaclname = $1;
			$ipv6 = 'ipv6';
			next;
		}
		elsif ($eaclname) {
			$result = $aclparser->acl($_);
		}
		elsif ($_=~m/^\S+/) {
			undef($eaclname);
			undef ($ipv6);
			next;
		}

		unless ($result) {
			$self->_debug("EPARSE: error parsing line: $_");
		}
		elsif ($result eq 'NOPARSE') {
			$self->_debug("NOPARSE: following line has been pre-parsed ($_)");
		}
		else {
			my ($iaclname,$iacltype,$pt);

			if ($eaclname) {
				$iaclname = $eaclname;
				$iacltype 	= $$result[1];
				$pt 		= $$result[2];   #Parse tree
			}
			else {
				$iaclname 	= $$result[0];
				$iacltype 	= $$result[1];
				$pt 		= $$result[2];   #Parse tree
			}
			#HERE
			#print Dumper($pt);
			my ($acltype,$seqno,$inproto,$proto,$dip,$dmask,$sip,$smask,$srcop,$dstop,$remark,$detail);
			my ($insrcport,$indstport,$instartsrcport,$inendsrcport,$instartdstport,$inenddstport,$inicmpcodetype);
			foreach my $key ('remark','seqno','acltype','extacltype','oldipv4addr','siptoke','diptoke') {	
				next unless ($$pt{$key});
				if ($key eq 'remark') {
					$remark = $$pt{'remark'}->{'__VALUE__'};
					$remark =~ s/remark (.*)/$1/g;
				}
				if ($key eq 'seqno') {
					$seqno = $$pt{'seqno'}->{'__VALUE__'};
				}
				if ($key eq 'acltype') {
					$acltype = $$pt{'acltype'}->{'__VALUE__'};
				}
				if ($key eq 'extacltype') {
					$acltype = $$pt{'extacltype'}->{'acltype'}->{'__VALUE__'};
					$inproto = $$pt{'extacltype'}->{'proto'}->{'__VALUE__'} || undef;
					if ($inproto) {
						my @protoarr = $self->_getprotobyname($inproto,$iacltype);
						if ($protoarr[1]) {		#Error check
							$self->_debug("ELOOKUP: Can't process protocol ($inproto) for line $_\n");
							next;
						}
						else {
							$proto = $protoarr[0];	#Result
						}
					}
				}
				if ($key eq 'oldipv4addr') {
					if ($$pt{'oldipv4addr'}->{'hdd32'}) {
						$dip   = $$pt{'oldipv4addr'}->{'hdd32'}->{'dd32'}->{'__VALUE__'};
						$dmask = $$pt{'oldipv4addr'}->{'mdd32'}->{'dd32'}->{'__VALUE__'};
					}
					elsif ($$pt{'oldipv4addr'}->{'dd32'}) {
						$dip = $$pt{'oldipv4addr'}->{'dd32'}->{'__VALUE__'};
					}
					else {
						$dip = 'any';
					}
				}
				if ($key eq 'siptoke') {
					my $iptoke = $$pt{'siptoke'}->{'iptoke'};
					my $ipv4addr = $iptoke->{'ipv4addr'};
					my $ipv6addr = $iptoke->{'ipv6addr'};
					if ($ipv4addr) {
						if ($ipv4addr->{'ipv4hostaddr'}) {
							$sip   = $ipv4addr->{'ipv4hostaddr'}->{'dd32'}->{'__VALUE__'};
						}
						elsif ($ipv4addr->{'ipv4maskaddr'}) {
							$sip   = $ipv4addr->{'ipv4maskaddr'}->{'hdd32'}->{'dd32'}->{'__VALUE__'};
							$smask = $ipv4addr->{'ipv4maskaddr'}->{'mdd32'}->{'dd32'}->{'__VALUE__'};
						}
						elsif ($ipv4addr->{'ipanyaddr'}) {
							$sip = 'any';
						}
					}
					elsif ($ipv6addr) {
						if ($ipv6addr->{'ch128'}) {
							$sip	= $ipv6addr->{'ch128'}->{'__VALUE__'};
							$sip=~s/\/128//g;
						}
						elsif ($ipv6addr->{'ipanyaddr'}) {
							$sip = 'any';
						}
					}
					if ($iptoke->{'compop'}) {
						my $op = $iptoke->{'compop'}->{'op'}->{'__VALUE__'};
						undef ($op) if ($op eq 'eq');	#EQ operations do not need an operator
						$insrcport = $iptoke->{'compop'}->{'port'}->{'__VALUE__'};
						my $port = $self->_getservbyname($insrcport,$inproto);
						unless ($port) {
							$self->_debug("ELOOKUP: Can't process service ($insrcport/$inproto) for line $_\n");
							next;
						}
						else {
							if ($op) {
								$srcop = "$op $port";
							}
							else {
								$srcop = $port;
							}
						}
					}
					elsif ($iptoke->{'rangeop'}) {
						my $op = 'range';
						$instartsrcport = $iptoke->{'rangeop'}->{'sport'}->{'port'}->{'__VALUE__'};
						$inendsrcport = $iptoke->{'rangeop'}->{'dport'}->{'port'}->{'__VALUE__'};
						my $startport = $self->_getservbyname($instartsrcport,$inproto);
						unless ($startport) {
							$self->_debug("ELOOKUP: Can't process service ($instartsrcport/$inproto) for line $_\n");
							next;
						}
						my $endport = $self->_getservbyname($inendsrcport,$inproto);
						unless ($endport) {
							$self->_debug("ELOOKUP: Can't process service ($inendsrcport/$inproto) for line $_\n");
							next;
						}
						$srcop = "$op $startport $endport";
					}
					
				}
				if ($key eq 'diptoke') {
					my $iptoke = $$pt{'diptoke'}->{'iptoke'};
					my $ipv4addr = $iptoke->{'ipv4addr'};
					my $ipv6addr = $iptoke->{'ipv6addr'};
					if ($ipv4addr) {
						if ($ipv4addr->{'ipv4hostaddr'}) {
							$dip   = $ipv4addr->{'ipv4hostaddr'}->{'dd32'}->{'__VALUE__'};
						}
						elsif ($ipv4addr->{'ipv4maskaddr'}) {
							$dip   = $ipv4addr->{'ipv4maskaddr'}->{'hdd32'}->{'dd32'}->{'__VALUE__'};
							$dmask = $ipv4addr->{'ipv4maskaddr'}->{'mdd32'}->{'dd32'}->{'__VALUE__'};
						}
						elsif ($ipv4addr->{'ipanyaddr'}) {
							$dip = 'any';
						}
					}
					elsif ($ipv6addr) {
						if ($ipv6addr->{'ch128'}) {
							$dip	= $ipv6addr->{'ch128'}->{'__VALUE__'};
							$dip=~s/\/128//g;
						}
						elsif ($ipv6addr->{'ipanyaddr'}) {
							$dip = 'any';
						}
					}
					if ($$pt{'diptoke'}->{'detail'}->{'__VALUE__'}) {
						$detail = $$pt{'diptoke'}->{'detail'}->{'__VALUE__'};
					}
					if ($iptoke->{'compop'}) {
						my $op = $iptoke->{'compop'}->{'op'}->{'__VALUE__'};
						undef ($op) if ($op eq 'eq');	#EQ operations do not need an operator
						$indstport = $iptoke->{'compop'}->{'port'}->{'__VALUE__'};
						$inicmpcodetype = $iptoke->{'compop'}->{'icmpcodetype'}->{'__VALUE__'};
						if ($inicmpcodetype) {
							my $icmpcodetype = $self->_icmptranslate($inicmpcodetype);
							$dstop = $icmpcodetype;
						}
						else {
							my $port = $self->_getservbyname($indstport,$inproto);
							unless ($port) {
								$self->_debug("ELOOKUP: Can't process service ($indstport/$inproto) for line $_\n");
								next;
							}
							else {
								if ($op) {
									$dstop = "$op $port";
								}
								else {
									$dstop = $port;
								}
							}
						}
					}
					elsif ($iptoke->{'rangeop'}) {
						my $op = 'range';
						$instartdstport = $iptoke->{'rangeop'}->{'sport'}->{'port'}->{'__VALUE__'};
						$inenddstport = $iptoke->{'rangeop'}->{'dport'}->{'port'}->{'__VALUE__'};
						my $startport = $self->_getservbyname($instartdstport,$inproto);
						unless ($startport) {
							$self->_debug("ELOOKUP: Can't process start service ($instartdstport/$inproto) for line $_\n");
							next;
						}
						my $endport = $self->_getservbyname($inenddstport,$inproto);
						unless ($endport) {
							$self->_debug("ELOOKUP: Can't process start service ($inenddstport/$inproto) for line $_\n");
							next;
						}
						$dstop = "$op $startport $endport";
					}
					
				}
					
			}
			#Insert into ACLDB
			if ($iacltype) {
				my $origline = $_;
				$origline .= " $logging" if ($logging);
		
				$iacltype = $ipv6 || $iacltype;

				if (($iacltype eq $ipv6) && ( ( $proto == 41 ) || ($inproto eq 'ipv6') ) ) { #don't allow proto 41 for v6
					undef ($proto);
					undef ($inproto);
				}


				#Convert mask(s) if exist
				if ($smask) { $smask = $self->_wildcard2natural($smask); };
				if ($dmask) { $dmask = $self->_wildcard2natural($dmask); };
					
				push (@{$acldb{$iacltype}{$iaclname}}, {

								acltype		=>	$acltype,
								seqno		=>	$seqno,
								srcip		=>	$sip,
								srcipv4mask 	=>	$smask,
								detail		=>	$detail,
								dstipv4mask 	=>	$dmask,
								dstip		=>	$dip,
								logging 	=>	$logging,
								proto		=>	$proto,
								inproto		=>	$inproto,
								origline 	=>	$origline,
								srcop 		=>	$srcop,
								insrcport	=>	$insrcport,
								instartsrcport	=>	$instartsrcport,
								inendsrcport	=>	$inendsrcport,
								dstop 		=>	$dstop,
								indstport	=>	$indstport,
								instartdstport	=>	$instartdstport,
								inenddstport	=>	$inenddstport,
								inicmpcodetype	=>	$inicmpcodetype,
								remark		=>	$remark,

								}
				);
			}
		}

	}	

	#print Dumper(%appdb);		#Dump the hashtables here before you proceed if you would like
	#print Dumper(%acldb);		#Dump the hashtables here before you proceed if you would like
	
	#Now recurse through the hashtables and start creating objects and binding them to rules
	foreach my $iacltype (sort keys %acldb) {	
		foreach my $iaclname (sort keys %{$acldb{$iacltype}}) {	### Creating Objects for $iacltype===[%]
			#Build the policy for the ACL first 
			my $rulepolicy;
			my $polname = "$iaclname:$iacltype";
	
			#Now stop here, we can't afford to create policies and rules for numbered ACLs
			#which apply to IOS lines, some IOS versions do not support named ACLs here so we must
			#skip creation of policies for these and purge them from the appdb
			if (
				($iacltype eq 'legacy') &&			#ACL is legacy
				($iaclname =~m/^(\d+)$/) &&			#ACL is numeric
				(
					($numacls{$iaclname}{'line'}) &&	#ACL defined on a line
					!($numacls{$iaclname}{'int'})		#ACL not defined on an int
				)
			) {

				$self->_debug("ACL $iaclname defined on lines and not on int, not creating policy for it");
				next;
			};

			unless ($poldb{$polname}) {
				my $poltype = ($iacltype eq 'ipv6') ? 'IPV6_ADDR' : 'IPV4_ADDR';	#Ternary!
				$rulepolicy = $self->{apm}->newPolicy (
                                                type            =>      $poltype,
                                                name            =>      $polname,
                                                enabled         =>      1,
				) || croak "Can't create policy with name $polname and type $poltype , this is FATAL"; 
				$poldb{$polname} = $rulepolicy;
				$acl2app{$iaclname} = $polname;
			}
			else {
				$rulepolicy = $poldb{$polname};
			}
			#Define a locally scoped annotation buffer, we will use this to hold the last remark made
			#and then populate the annotation aclent for each rule based on it before finally clearing it out
			my $ruleannotation;
			foreach my $aclent (@{$acldb{$iacltype}{$iaclname}}) {
				my ($ruleorigline,$ruleseqno,$ruleaction,$ruledetail,$ruleprotoobj,$rulesrcipobj,$rulesrcopobj,$ruledstipobj,$ruledstopobj);
				#Buffer remarks
				if ($aclent->{remark}) {
					$ruleannotation = $aclent->{remark};	#Overwrite last buffered remark
					next;
				}
				$ruleaction = $aclent->{acltype};
				$ruleseqno = $aclent->{seqno};
				$ruledetail = $aclent->{logging};
				$ruleorigline = $aclent->{origline};
				my $srcip = $aclent->{srcip};
				my $srcipv4mask = $aclent->{srcipv4mask};
				my $srcipname;
				if (($srcip) && ($srcip ne 'any')) {	#Any never gets defined
					my $srcipname;
					if ($srcipv4mask) {
						my $tmpsrcipname = "$srcip\/$srcipv4mask\n";
						my $nnm = Net::Netmask->new($tmpsrcipname);
						$srcipname = $nnm->base . "\/" . $nnm->bits;
					}
					else {
						$srcipname = $srcip;
					}
					unless (defined ($objectdb{$srcipname}))	{	#Decache where we know about this
						my $type = ($iacltype eq 'ipv6') ? 'IPV6_ADDR' : 'IPV4_ADDR';	#Ternary!
						my $object = $self->{apm}->newObject (
									type	=>	$type,
									name	=>	$srcipname,
									value	=>	$srcipname,	#Also name since it has mask
									enabled	=>	1,
						) || croak "Can't create object with name $srcipname and value $srcipname and type $type , this is FATAL";
						$objectdb{$srcipname} = $object;	#Recache
						$rulesrcipobj = $object;
					}
					else {
						$rulesrcipobj = $objectdb{$srcipname};
					}
				}
				my $dstip = $aclent->{dstip};
				my $dstipv4mask = $aclent->{dstipv4mask};
				my $dstipname;
				if (($dstip) && ($dstip ne 'any')) {	#Any never gets defined
					my $dstipname;
					if ($dstipv4mask) {
						my $tmpdstipname = "$dstip\/$dstipv4mask\n";
						my $nnm = Net::Netmask->new($tmpdstipname);
						$dstipname = $nnm->base . "\/" . $nnm->bits;
					}
					else {
						$dstipname = $dstip;
					}
					unless (defined ($objectdb{$dstipname})){	#Decache where we know about this
						my $type = ($iacltype eq 'ipv6') ? 'IPV6_ADDR' : 'IPV4_ADDR';	#Ternary!
						my $object = $self->{apm}->newObject (
									type	=>	$type,
									name	=>	$dstipname,
									value	=>	$dstipname,	#Also name since it has mask
									enabled	=>	1,
						) || croak "Can't create object with name $dstipname and value $dstipname and type $type , this is FATAL";
						$objectdb{$dstipname} = $object;	#Recache
						$ruledstipobj = $object;
					}
					else {
						$ruledstipobj = $objectdb{$dstipname};
					}
				}
				my $proto = $aclent->{proto};
				my $protoname = $aclent->{inproto} || "proto_$proto";
				if ($proto) {
					unless (defined ($objectdb{$protoname})) {	#Decache where we know about this
						my $object = $self->{apm}->newObject (
									type	=>	'IP_PROTO',
									name	=>	$protoname,
									value	=>	$proto,
									enabled	=>	1,
						) || croak "Can't create object with name $protoname and value $proto and type IP_PROTO , this is FATAL";
						$objectdb{$protoname}=$object;
						$ruleprotoobj = $object;
					}
					else {
						$ruleprotoobj = $objectdb{$protoname};
					}
				}
				my $srcop = $aclent->{srcop};
				if ($srcop) {
					unless (defined ($objectdb{$srcop})) {      #Decache where we know about this
						my ($srcoptype,$srcopname);
						my $inproto = $aclent->{inproto};
						if    ($inproto eq 'tcp') {	
								$srcoptype = 'TCP_PORT';	
								if ($srcop=~m/range/) {
									$srcopname = "range_$aclent->{instartsrcport}_$aclent->{inendsrcport}";
								}
								elsif ($srcop=~m/(\w+) (\d+)/) {
									$srcopname = "$1 $aclent->{insrcport}";
								}
								elsif ($srcop=~m/(\d+)/) {
									$srcopname = $aclent->{insrcport};
								}
								else {
									$srcopname = $srcop;
								}
						}
						elsif ($inproto eq 'udp') {	
								$srcoptype = 'UDP_PORT';	
								if ($srcop=~m/range/) {
									$srcopname = "range_$aclent->{instartsrcport}_$aclent->{inendsrcport}";
								}
								elsif ($srcop=~m/(\w+) (\d+)/) {
									$srcopname = "$1 $aclent->{insrcport}";
								}
								elsif ($srcop=~m/(\d+)/) {
									$srcopname = $aclent->{insrcport};
								}
								else {
									$srcopname = $srcop;
								}
						}
						else {
							$srcopname = $srcop;
						}
						if ($srcoptype) {
							
	                                                my $object = $self->{apm}->newObject (
	                                                                        type    =>      $srcoptype,
	                                                                        name    =>      $srcopname,
	                                                                        value   =>      $srcop,
	                                                                        enabled =>      1,
							) || croak "Can't create object with name $srcopname and value $srcop and type $srcoptype , this is FATAL";
	
							$objectdb{$srcop}=$object;
		
							$rulesrcopobj = $object;
						}

                                        }
					else {
							$rulesrcopobj = $objectdb{$srcop};
					}
                                }
				my $dstop = $aclent->{dstop};
				if ($dstop) {
					unless (defined ($objectdb{$dstop})) {      #Decache where we know about this
						my ($dstoptype,$dstopname);
						my $inproto = $aclent->{inproto};
						if    ($inproto eq 'tcp') {	
								$dstoptype = 'TCP_PORT';	
								if ($dstop=~m/range/) {
									$dstopname = "range_$aclent->{instartdstport}_$aclent->{inenddstport}";
								}
								elsif ($dstop=~m/(\w+) (\d+)/) {
									$dstopname = "$1 $aclent->{indstport}";
								}
								elsif ($dstop=~m/(\d+)/) {
									$dstopname = $aclent->{indstport};
								}
								else {
									$dstopname = $dstop;
								}
						}
						elsif ($inproto eq 'udp') {	
								$dstoptype = 'UDP_PORT';	
								if ($dstop=~m/range/) {
									$dstopname = "range_$aclent->{instartdstport}_$aclent->{inenddstport}";
								}
								elsif ($dstop=~m/(\w+) (\d+)/) {
									$dstopname = "$1 $aclent->{indstport}";
								}
								elsif ($dstop=~m/(\d+)/) {
									$dstopname = $aclent->{indstport};
								}
								else {
									$dstopname = $dstop;
								}
						}
						elsif ($inproto eq 'icmp'){	
								$dstoptype = 'ICMP_TYPECODE';	
								$dstopname = $aclent->{inicmpcodetype} || $dstop;
						}
						else {
							$dstopname = $dstop;
						}

						#Add detail to the dstop if it exists
						$dstop .= " $aclent->{detail}" if ($aclent->{detail});

						if ($dstoptype) {

	                                                my $object = $self->{apm}->newObject (
	                                                                        type    =>      $dstoptype,
	                                                                        name    =>      $dstopname,
	                                                                        value   =>      $dstop,
	                                                                        enabled =>      1,
							) || croak "Can't create object with name $dstopname and value $dstop and type $dstoptype , this is FATAL";

                                                        $objectdb{$dstop}=$object;
							$ruledstopobj = $object;
						}

                                        }
					else {
							$ruledstopobj = $objectdb{$dstop};
					}
							
				}

				#See what we got out of that
				my %rulehash;
				$rulehash{	'pol_id'	} 	= 	$rulepolicy;
				$rulehash{	'pol_seq'	} 	= 	$ruleseqno;
				$rulehash{	'action'	} 	= 	$ruleaction;
				$rulehash{	'proto_obj'	} 	= 	$ruleprotoobj 	if ($ruleprotoobj);
				$rulehash{	's_ip_obj'	}	=	$rulesrcipobj	if ($rulesrcipobj);
				$rulehash{	's_port_obj'	}	=	$rulesrcopobj	if ($rulesrcopobj);
				$rulehash{	'd_ip_obj'	}	=	$ruledstipobj	if ($ruledstipobj);
				$rulehash{	'd_port_obj'	}	=	$ruledstopobj	if ($ruledstopobj);
				$rulehash{	'flags'		}	=	$ruledetail	if ($ruledetail);
				$rulehash{	'annotation'	}	=	$ruleannotation	if ($ruleannotation);
				$rulehash{	'enabled'	}	=	1;

				my $rule = $self->{apm}->newRule(%rulehash);	
				#print "------------------------------\n";	#Dump the rule create state if you would like
				#print "$ruleorigline\n\n";
				#print Dumper($rule);
				#print "------------------------------\n";

				#Clear annotation buffer so that remarks do not persist to the next aclent
				undef($ruleannotation);
				

			}

		}
	}

	#Now work on creating the applications
	foreach my $interface (sort keys %appdb) {	### Creating Applications for $hostname===[%]
		foreach my $type (sort keys %{$appdb{$interface}}) {
			for my $direction (sort keys %{$appdb{$interface}{$type}}) {
				my $aclname = $appdb{$interface}{$type}{$direction};
				my $polname = $acl2app{$aclname};
				my $policy  = $poldb{$polname};
				$self->_debug("Creating application type $type interface $interface, direction $direction, for aclname $aclname, polname $polname");
				croak "Internal Error: Can't locate policy $polname" unless ($policy);
							
				my $app = $self->{apm}->newApplication (
							pol_id		=>	$policy,
							router		=>	$hostname,
							interface	=>	$interface,
							direction	=>	$direction,
							enabled		=>	1,
				);
			}
						
		}
	}

}       

#SUBS LIVE UNDER HERE
#Getservbyname wrapper
sub _getservbyname {	

	my $self = shift;	
	my $service = shift;
	my $proto = shift;

	return ($service) if ($service =~ m/^\d+$/);	#Numerics get passed back out as numerics, despite lack of proto

	return unless ($service && $proto);

	return 515 if ($service eq 'lpd' && ($proto eq 'tcp' || $proto eq 'udp'));	#Hack for IOS dodgy servicemap

	return ($cache{'service'}{$proto}{$service})  if ($cache{'service'}{$proto}{$service});	#Retrieve from cache if we have it
	
	my ($name, $aliases, $port, $proto) = getservbyname ($service,$proto);

	unless ($port) {
		$self->_debug ("Unable to locate service id for service '$service' will have to return undef");
		return;
	}
	else {
		$cache{'service'}{$proto}{$service} = $port;	#Populate cache
		return ($port);
	}

}

#Getprotobyname wrapper
sub _getprotobyname {

	my $self = shift;
	my $proto = shift;
	my $iacltype = shift;
	my @noerr = (undef,undef);
	my @err = (undef,1);

	return ($proto) if ($proto =~ m/^\d+$/);		#Numerics get passed back out as numerics

	return (@err) unless ($proto && $iacltype);

	return (@noerr) if ($iacltype eq 'ipv6' && $proto eq 'ipv6');#Return no err for ipv6 in an ipv6 acl (meaningless)

	return (@noerr) if ($proto eq 'ip');				#Return no err for ip in ipv4 acl (meaningless)

	return ($cache{'proto'}{$proto})  if ($cache{'proto'}{$proto});	#Retrieve from cache if we have it

	my ($name, $aliases, $protocol_number) = getprotobyname ($proto);

	unless ($protocol_number) {
		$self->_debug ("Unable to locate protocol id for protocol '$proto' will have to return err");
		return(@err);
	}
	else {
		$cache{'proto'}{$proto} = $protocol_number;	#Populate cache
		return ($protocol_number,undef);
	}

}

#wildcard to natural

sub _wildcard2natural {

	my $self = shift;
	my $wildcard = shift;

	return unless ($wildcard);

	if ($wildcard =~ m/(\d+)\.(\d+)\.(\d+)\.(\d+)/) {
		return ($cache{'wildcard2mask'}{$wildcard}) if ($cache{'wildcard2mask'}{$wildcard}); #Retrieve from cache if we have it
		my @octets = ($1,$2,$3,$4);
		foreach my $octet (@octets) {
			if ($octet > 255) {
				$self->_debug ("Unable to convert illegal mask $wildcard");
				return;
			}
			$octet = 255-$octet;
		}
		my $naturalmask = "$octets[0].$octets[1].$octets[2].$octets[3]";
		if ($naturalmask eq "255.255.255.127") { $naturalmask = "255.255.255.128" };	#Fix silly cisco bug
		$cache{'wildcard2mask'}{$wildcard}=$naturalmask;	#Populate cache
		return ($naturalmask);
	}
	else {
		$self->_debug ("Unable to convert illegal mask $wildcard");
		return;
	}

}

#populate ICMP cache
sub _popicmpcache {

	$cache{icmp}{'echo-reply'}			= 	"999999999";	#Work around null echo-reply typecode
	$cache{icmp}{'unreachable'}			= 	"3";
	$cache{icmp}{'net-unreachable'}			= 	"3 0";
	$cache{icmp}{'host-unreachable'}		= 	"3 1";
	$cache{icmp}{'protocol-unreachable'}		= 	"3 2";
	$cache{icmp}{'port-unreachable'}		= 	"3 3";
	$cache{icmp}{'packet-too-big'}			= 	"3 4";
	$cache{icmp}{'source-route-failed'}		= 	"3 5";
	$cache{icmp}{'network-unknown'}			= 	"3 6";
	$cache{icmp}{'host-unknown'}			= 	"3 7";
	$cache{icmp}{'host-isolated'}			= 	"3 8";
	$cache{icmp}{'dod-net-prohibited'}		= 	"3 9";
	$cache{icmp}{'dod-host-prohibited'}		= 	"3 10";
	$cache{icmp}{'net-tos-unreachable'}		= 	"3 11";
	$cache{icmp}{'host-tos-unreachable'}		= 	"3 12";
	$cache{icmp}{'administratively-prohibited'}	= 	"3 13";
	$cache{icmp}{'host-precedence-unreachable'}	= 	"3 14";
	$cache{icmp}{'precedence-unreachable'}		= 	"3 15";
	$cache{icmp}{'source-quench'}			= 	"3 15";
	$cache{icmp}{'redirect'}			= 	"5";
	$cache{icmp}{'net-redirect'}			= 	"5 0";
	$cache{icmp}{'host-redirect'}			= 	"5 1";
	$cache{icmp}{'net-tos-redirect'}		= 	"5 2";
	$cache{icmp}{'host-tos-redirect'}		= 	"5 3";
	$cache{icmp}{'alternate-address'}		= 	"6";
	$cache{icmp}{'echo'}				= 	"8";
	$cache{icmp}{'echo-request'}			= 	"8";
	$cache{icmp}{'router-advertisement'}		= 	"9";
	$cache{icmp}{'router-solicitation'}		= 	"10";
	$cache{icmp}{'time-exceeded'}			= 	"11";
	$cache{icmp}{'ttl-exceeded'}			= 	"11 0";
	$cache{icmp}{'reassembly-timeout'}		= 	"11 1";
	$cache{icmp}{'parameter-problem'}		= 	"12";
	$cache{icmp}{'general-parameter-problem'}	= 	"12 0";
	$cache{icmp}{'option-missing'}			= 	"12 1";
	$cache{icmp}{'no-room-for-option'}		= 	"12 2";
	$cache{icmp}{'timestamp-request'}		= 	"13";
	$cache{icmp}{'timestamp-reply'}			= 	"14";
	$cache{icmp}{'information-request'}		= 	"15";
	$cache{icmp}{'information-reply'}		= 	"16";
	$cache{icmp}{'mask-request'}			= 	"17";
	$cache{icmp}{'mask-reply'}			= 	"18";
	$cache{icmp}{'traceroute'}			= 	"30";
	$cache{icmp}{'conversion-error'}		= 	"31";

	#build grammar with hyphenated keys first since they 
	#are longer matches and the parser requires they come first

	my (@grammar,@grammar1,@grammar2);	
	foreach my $noun (sort keys %{$cache{icmp}})	{
		if ($noun=~m/-/) {
			push (@grammar1,$noun);
		}
		else {
			push (@grammar2,$noun);
		}
	}

	@grammar = (@grammar1, @grammar2);

	$icmpgrammar = join ('|', @grammar);

	return;

}

#icmptranslate
sub _icmptranslate {

	my $self = shift;

	my $icmpstring = shift;

	return unless ($icmpstring);

	return ($icmpstring) if ($icmpstring=~m/^\d+ \d+$/);	#Numerics get passed back out as numerics

	return ($cache{'icmp'}{$icmpstring}) if (defined($cache{'icmp'}{$icmpstring}));	#Retrieve from the cache if we have it

	$self->_debug ("Warning: unable to decache icmpstring ($icmpstring)");

	return ($icmpstring);

}
	
1;
