#!/usr/bin/perl

package APM::Policy::Rule;

use APM::DBI;
use APM::AppHandler;
use APM::Object;
use strict;
use Carp;
use Readonly;
use Data::Dumper;
use Scalar::Util 'blessed';



=pod

=head1 NAME

        APM::Policy::Rule

=head1 ABSTRACT

        Class to implement an Access Policy Manager Policy Rule

=head1 SYNOPSIS

	use APM;
        use APM::Policy::Rule;

        #################
        # class methods #
        #################
        $apmPolicyRuleRule    = APM::Policy::Rule->new   (                     #Initialise class

                                                debug => [0|1|2],       #Debug can be switched on, 1 is standard, 2 is with callstack
                                        	debugfile => $filename, #Debug can be sent to a file instead of STDOUT
                                        	debugstream => [0|1]    #Debug can be mirrored to a stream as well
                                                                	#Call getDebugStream to retrieve

						dbi => APM::DBI		#APM DBI object if you dont want to open a new DB connection

                                                apphandler => APM::AppHandler   #APM Application Handler object if you do not wish to
                                                                                #Open a new one

						[id]		=>	[optional: overwrite an existing rule by ID]
						pol_id		=>	An APM::Policy object
						pol_seq		=>	Sequence number in policy
						action		=>	String, either 'permit' or 'deny'
						proto_obj	=>	An APM::Object representing an IP Protocol
						s_ip_obj	=>	An APM::Object representing a source IP Address
						s_port_obj	=>	An APM::Object representing a source TCP/UDP port
						d_ip_obj	=>	An APM::Object representing a dest IP Address
						d_port_obj	=>	An APM::Object representing a dest TCP/UDP port
						flags		=>	A string of flags (not currently supported)
						annotation	=>	An annotation string
						enabled		=>	APM Policy Rule enabled state (1 or 0)


                                );

	$apmPolicyRule->load 			($id)		#Returns a populated APM::Policy::Rule

	$apmPolicyRule->commit();			#Commits the policy rule change to the database, populates the policy ID

	$apmPolicyRule->destroy();			#Deletes the policy rule from the policy rule store

	$apmPolicyRule->setSeq			($seq)	#Sets the sequence number of the rule;

        #######################
        # object data methods #
        #######################


	$apmPolicyRule->getID();			#Retrieve the ID of a committed object
	$apmPolicyRule->getPolID();			#Retrieve the parent policy object ID
	$apmPolicyRule->getPolSeq();			#Retrieve the Sequence of the policy rule within the parent
	$apmPolicyRule->getAction();			#Retrieve the action
	$apmPolicyRule->getProtoObj();			#Retrieve the protocol object
	$apmPolicyRule->getSIPObj();			#Retrieve the source IP object
	$apmPolicyRule->getSPortObj();			#Retrieve the source IP port
	$apmPolicyRule->getDIPObj();			#Retrieve the dest IP object
	$apmPolicyRule->getDPortObj();			#Retrieve the dest IP port
	$apmPolicyRule->getFlags();			#Retrieve the flags
	$apmPolicyRule->getAnnotation();		#Retrieve the annotation
	$apmPolicyRule->getEnabled();			#Retrieve the enabled state


	######################
	# object properties  #
	######################

	These properties are READ ONLY

        _id                     =	Policy Rule ID
        _pol_id	                =	Parent Policy ID
        _action                 =	Action
        _proto_obj              =	Protocol Referenced
        _s_ip_obj               =	Source object referenced
        _s_port_obj             =	Source object tcp/udp port referenced,
        _d_ip_obj               =	Destination object referenced
        _d_port_obj             =	Destination object tcp/udp port referenced,
        _flags                  =	Flags
        _annotation             =	Annotation
        _enabled                =	Rule enabled state

	These properties are READ/WRITE

        _pol_seq                =	Policy Sequence

=head1 DESCRIPTION

use APM::Object;
use APM::Policy;
use APM::Policy::Rule;

my $apmrule = APM::Policy::Rule->new (

                                                pol_id          =>      APM::Policy->load("foo"),
                                                pol_seq         =>      10,
                                                action          =>      permit,
                                                proto_obj       =>      APM::Object->load("TCP"),
                                                s_ip_obj        =>      APM::Object->load("host1"),
                                                s_port_obj      =>      APM::Object->load("port1"),
                                                d_ip_obj        =>      APM::Object->load("host2"),
                                                d_port_obj      =>      APM::Object->load("port2"),
                                                annotation      =>      'Example',
                                                enabled         =>      1,
);

$apmrule->commit;	

We advise you to create rules using the APM interface (newRule)

=head1 TODO

        Tidy POD

=cut


my $dbi;
my $types;
my $typesbyid;

my $apphandler;

sub new
{
 my $proto = shift;
 my $class = ref $proto || $proto;

 my $this = {
	_id 			=> undef,
	_pol_id			=> undef,
	_pol_seq		=> undef,
	_action			=> undef,
	_proto_obj		=> undef,
	_s_ip_obj		=> undef,
	_s_port_obj		=> undef,
	_d_ip_obj		=> undef,
	_d_port_obj		=> undef,
	_flags			=> undef,
	_annotation		=> undef,
	_enabled		=> undef,

 };
	
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

 if ($this->{in_apphandler}) {
        if ((blessed ($this->{in_apphandler})) && $this->{in_apphandler}->isa('APM::AppHandler')) {
                $this->_debug("We were passed a valid APM::AppHandler object, using it...");
                $apphandler = $this->{in_apphandler};
        }
        else {
                croak "$class requires a valid APM::AppHandler  object to be passed";
        }
 }
 else {
         #Initialise the Application Handler
         $this->_debug("We were NOT passed a valid APM::AppHandler object, constructing one...");
         $apphandler = APM::AppHandler->new(
                                                debug           =>      $this->{_debug},
                                                debugfile       =>      $this->{_debugfile},
                                                debugstream     =>      $this->{_debugstream},
                                                dbi             =>      $dbi,
         ) || croak "Couldn't initialise Application Handler !";
 }


 $types = $dbi->{types};
 $typesbyid = $dbi->{typesbyid};

 #Trust all IDs we are given since we may need to overwrite objects
 if ($this->{in_id} =~ m/\d+/) {
	Readonly $this->{_id} => $this->{in_id};
 }


 if ((blessed ($this->{in_pol_id})) && $this->{in_pol_id}->isa('APM::Policy')) {
	unless ($this->{in_pol_id}->getID) {
		croak "Erk, this policy hasn't been committed! ABORT!";
	}
	Readonly $this->{_pol_id} => $this->{in_pol_id};
 }
 
 if ($this->{in_pol_seq}  =~ m/\d+/) {
	unless (($this->{in_pol_seq} > 0) && ($this->{in_pol_seq} < 65536)) {
		croak "Invalid Policy Sequence Number (must be between 1 and 65535)!";
	}
	my $polid = $this->{_pol_id}->getID;
	unless ($polid) {
		croak "Can't insert sequence number because we can't arbitrate (unaware of other rules) due to lack of parent policy id!!";
	}
	my $results = $dbi->query("select pol_seq from policy_rules where pol_id='$polid' and pol_seq = '$this->{in_pol_seq}';");
	
	#croak "Duplicate policy sequence number $this->{in_pol_seq} for policy $polid" if ($$results[0]);
	
	$this->{_pol_seq} = $this->{in_pol_seq};	#Policy sequence does not need to be read only 
							#And regularly gets changed
 }

 if ($this->{in_action}) {
	unless ( ($this->{in_action} eq 'permit') || ($this->{in_action} eq 'deny') ) {
		croak "Action must be 'permit' or 'deny'";
	}
	
	Readonly $this->{_action} => $this->{in_action};
 }

 if ((blessed ($this->{in_proto_obj})) && $this->{in_proto_obj}->isa('APM::Object')) {
	if (
		($this->{in_proto_obj}->getType == $types->{IP_PROTO}) ||
		($this->{in_proto_obj}->getObjGroupType == $types->{IP_PROTO}) 
	) {
		unless ($this->{in_proto_obj}->getID) {
			croak "Erk, this object hasn't been committed! ABORT!";
		}
		Readonly $this->{_proto_obj} => $this->{in_proto_obj};
	}
	else {
		croak "proto_obj MUST be an object of type IP_PROTO";
	}
 }

 if ((blessed ($this->{in_s_ip_obj})) && $this->{in_s_ip_obj}->isa('APM::Object')) {
        if (
                ($this->{in_s_ip_obj}->getType == $types->{IPV4_ADDR}) ||
                ($this->{in_s_ip_obj}->getObjGroupType == $types->{IPV4_ADDR}) ||
                ($this->{in_s_ip_obj}->getType == $types->{IPV6_ADDR}) ||
                ($this->{in_s_ip_obj}->getObjGroupType == $types->{IPV6_ADDR})
        ) {
		if ($this->{in_pol_id}->getType == $this->{in_s_ip_obj}->getType) {
			unless ($this->{in_s_ip_obj}->getID) {
				croak "Erk, this object hasn't been committed! ABORT!";
			}
                	Readonly $this->{_s_ip_obj} => $this->{in_s_ip_obj};
		}
		else {
			croak "s_ip_obj MUST be the correct type for this policy!!";
		}
        }
	else {
		croak "s_ip_obj MUST be of type IPV4_ADDR or of type IPV6_ADDR";
	}
 }

 if ((blessed ($this->{in_d_ip_obj})) && $this->{in_d_ip_obj}->isa('APM::Object')) {
        if (
                ($this->{in_d_ip_obj}->getType == $types->{IPV4_ADDR}) ||
                ($this->{in_d_ip_obj}->getObjGroupType == $types->{IPV4_ADDR}) ||
                ($this->{in_d_ip_obj}->getType == $types->{IPV6_ADDR}) ||
                ($this->{in_d_ip_obj}->getObjGroupType == $types->{IPV6_ADDR})
        ) {
		if ($this->{in_pol_id}->getType == $this->{in_d_ip_obj}->getType) {
			unless ($this->{in_d_ip_obj}->getID) {
				croak "Erk, this object hasn't been committed! ABORT!";
			}
                	Readonly $this->{_d_ip_obj} => $this->{in_d_ip_obj};
		}
                else {
                        croak "d_ip_obj MUST be the correct type for this policy!!";
                }
        }
        else {  
                croak "d_ip_obj MUST be of type IPV4_ADDR or of type IPV6_ADDR";
	}
 }

 if ((blessed ($this->{in_s_port_obj})) && $this->{in_s_port_obj}->isa('APM::Object')) {
        if (
                ($this->{in_s_port_obj}->getType == $types->{TCP_PORT}) ||
                ($this->{in_s_port_obj}->getType == $types->{UDP_PORT}) ||
                ($this->{in_s_port_obj}->getObjGroupType == $types->{TCP_PORT}) ||
                ($this->{in_s_port_obj}->getObjGroupType == $types->{UDP_PORT})
        ) {
		unless ($this->{in_s_port_obj}->getID) {
			croak "Erk, this object hasn't been committed! ABORT!";
		}
                Readonly $this->{_s_port_obj} => $this->{in_s_port_obj};
        }
        else {  
                croak "s_port_obj MUST be of type TCP_PORT or of type UDP_PORT";
        }
 }

 if ((blessed ($this->{in_d_port_obj})) && $this->{in_d_port_obj}->isa('APM::Object')) {
        if (
                ($this->{in_d_port_obj}->getType == $types->{ICMP_TYPECODE}) ||
                ($this->{in_d_port_obj}->getType == $types->{TCP_PORT}) ||
                ($this->{in_d_port_obj}->getType == $types->{UDP_PORT}) ||
                ($this->{in_d_port_obj}->getObjGroupType == $types->{TCP_PORT})  ||
                ($this->{in_d_port_obj}->getObjGroupType == $types->{UDP_PORT})  ||
                ($this->{in_d_port_obj}->getObjGroupType == $types->{ICMP_TYPECODE}) 
        ) {
		unless ($this->{in_d_port_obj}->getID) {
			croak "Erk, this object hasn't been committed! ABORT!";
		}
                Readonly $this->{_d_port_obj} => $this->{in_d_port_obj};
        }
        else {  
                croak "d_port_obj MUST be of type TCP_PORT or of type UDP_PORT or of type ICMP_TYPECODE";
        }
 }

 if ($this->{in_flags}) {
		Readonly $this->{_flags} => $this->{in_flags};
 }

 if ($this->{in_annotation}) {
	Readonly $this->{_annotation}	=>	$this->{in_annotation};
 }

 if (defined($this->{in_enabled})) {
	croak "Enabled must be 0 or 1" if (
						($this->{in_enabled}) && 
						!(
							($this->{in_enabled} == 0) || 
							($this->{in_enabled} == 1)
						)
	);
	Readonly $this->{_enabled} => $this->{in_enabled};
 }

 #Clean out all the input fields
 foreach my $inkey (sort keys %{$this}) {
	if ($inkey=~m/^in_/) {
		delete $this->{$inkey};
	}
 };

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

sub getID {			#Retrieve ID
	my $self = shift;
	return ($self->{_id});
}
sub getPolID {			#Get parent policy object id
	my $self = shift;
	return ($self->{_pol_id});
}
sub getPolSeq {			#Get sequence of policy rule
	my $self = shift;
        return ($self->{_pol_seq});
}
sub getAction {			#Get policy action
	my $self = shift;
        return ($self->{_action});
}
sub getProtoObj {		#Get protocol object
	my $self = shift;
        return ($self->{_proto_obj});
}
sub getSIPObj {			#Get source IP Object
        my $self = shift;
        return ($self->{_s_ip_obj});
}
sub getSPortObj {		#Get source port object
        my $self = shift;
        return ($self->{_s_port_obj});
}
sub getDIPObj {                 #Get dest IP Object
        my $self = shift;
        return ($self->{_d_ip_obj});
}
sub getDPortObj {               #Get dest port object
        my $self = shift;
        return ($self->{_d_port_obj});
}              
sub getFlags {			#Get flags
	my $self = shift;
	return ($self->{_flags});
}
sub getAnnotation {		#Get annotation
	my $self = shift;
	return ($self->{_annotation});
}
sub getEnabled {		#Retrieve enabled
	my $self = shift;
	return ($self->{_enabled});
}

sub load   {			#Load from database

	my $self = shift;

	my $id = shift;


	unless ($id=~m/\d+/) {
		croak "Invalid ID, Could not load Rule with id $id";
	}

	$self->_debug("loading Rule with ID $id");


	my $sql = "select * from policy_rules where id='$id';";

	my $results = $dbi->query($sql);

	unless ($$results[0]) {
		croak "Rule with ID $id not found in Rule store";
	}
	else {
		my ($pol_id,$proto_obj,$s_ip_obj,$s_port_obj,$d_ip_obj,$d_port_obj);
		my $pol_id 	=  APM::Policy->new; $pol_id		->	load($$results[0]->{pol_id});
		if ($$results[0]->{proto_obj}) {
			$proto_obj   =  APM::Object->new; $proto_obj         ->      load($$results[0]->{proto_obj});
		}
		if ($$results[0]->{s_ip_obj}) {
			$s_ip_obj    =  APM::Object->new; $s_ip_obj          ->      load($$results[0]->{s_ip_obj});
		}
		if ($$results[0]->{s_port_obj}) {
			$s_port_obj  =  APM::Object->new; $s_port_obj        ->      load($$results[0]->{s_port_obj});
		}
		if ($$results[0]->{d_ip_obj}) {
			$d_ip_obj    =  APM::Object->new; $d_ip_obj          ->      load($$results[0]->{d_ip_obj});
		}
		if ($$results[0]->{d_port_obj}) {
			$d_port_obj  =  APM::Object->new; $d_port_obj        ->      load($$results[0]->{d_port_obj});
		}
		Readonly $self->{_id} 		=> 	$$results[0]->{id};
		Readonly $self->{_pol_id}	=>	$pol_id;
		Readonly $self->{_action}	=>	$$results[0]->{action};
		Readonly $self->{_proto_obj}	=>	$proto_obj;
		Readonly $self->{_s_ip_obj}	=>	$s_ip_obj;
		Readonly $self->{_s_port_obj}	=>	$s_port_obj;
		Readonly $self->{_d_ip_obj}	=>	$d_ip_obj;
		Readonly $self->{_d_port_obj}	=>	$d_port_obj;
		Readonly $self->{_annotation}	=>	$$results[0]->{annotation};
		Readonly $self->{_flags}	=>	$$results[0]->{flags};
		Readonly $self->{_enabled} 	=> 	$$results[0]->{enabled};
		$self->{_pol_seq}		=	$$results[0]->{pol_seq};
	}

	return 1;


}

sub commit {			#Commit to database, return ID on success

	my $self = shift;

	$self->_debug("Committing rule to DB...");

	#Dont allow bad commits
	croak "Rule must be attached to a parent policy" unless ($self->{_pol_id});
	croak "Rule must have a sequence number" unless ($self->{_pol_seq});
	croak "Rule must have an action" unless ($self->{_action});

	croak "Rule can not specify TCP_PORT, UDP_PORT or ICMP_TYPECODE objects without TCP, UDP or ICMP protocol type specified" if (
			(
				($self->{_s_port_obj})	||
				($self->{_d_port_obj})
			)	&&
			(
				!( $self->{_proto_obj} ) ||
				!(
					($self->{_proto_obj}->getName eq 'TCP') || 
					($self->{_proto_obj}->getName eq 'UDP') || 
					($self->{_proto_obj}->getName eq 'ICMP')
				)
			)

	);

	$self->{_enabled} = 1 unless (defined($self->{_enabled}));

	my $sql;
	my $id;

	my ($_pol_id,$_proto_obj_id,$_s_ip_obj_id,$_s_port_obj_id,$_d_ip_obj_id,$_d_port_obj_id);

	#use termary operator such as to protect failures, Must use NULL if stuff doesn't exist to preserve database
	#integrity
	#
	#
	$self->{_pol_id}	?	( $_pol_id = "'".$self->{_pol_id}->getID."'" )			:	($_pol_id = 'NULL');
	$self->{_proto_obj}	?	( $_proto_obj_id = "'".$self->{_proto_obj}->getID."'" )		:	($_proto_obj_id = 'NULL');
	$self->{_s_ip_obj}	?	( $_s_ip_obj_id = "'".$self->{_s_ip_obj}->getID."'" )		:	($_s_ip_obj_id = 'NULL');
	$self->{_s_port_obj}	?	( $_s_port_obj_id = "'".$self->{_s_port_obj}->getID."'" )	:	($_s_port_obj_id = 'NULL');
	$self->{_d_ip_obj}	?	( $_d_ip_obj_id = "'".$self->{_d_ip_obj}->getID."'" )		:	($_d_ip_obj_id = 'NULL');
	$self->{_d_port_obj}	?	( $_d_port_obj_id = "'".$self->{_d_port_obj}->getID."'" )	:	($_d_port_obj_id = 'NULL');

	if ($self->{_id}) {


                $sql = "update policy_rules set 
						pol_id		=		$_pol_id,
						pol_seq		=		'$self->{_pol_seq}',
						action		=		'$self->{_action}',
						proto_obj	=		$_proto_obj_id,
						s_ip_obj	=		$_s_ip_obj_id,
						s_port_obj	=		$_s_port_obj_id,
						d_ip_obj	=		$_d_ip_obj_id,
						d_port_obj	=		$_d_port_obj_id,
						flags		=		'$self->{_flags}',
						annotation	=		'$self->{_annotation}',
						enabled		=		'$self->{_enabled}'
                                         where id = '$self->{_id}';
                ";

                my $id = $self->{_id};

                $dbi->do($sql) || croak ("couldn't commit rule $!");

                $self->_debug("Rule commit success, ID was $id sequence was $self->{_pol_seq}...");

	}

	else {

		$sql = "insert into policy_rules 
								(id, pol_id, pol_seq, action, 
								proto_obj, s_ip_obj, s_port_obj, 
								d_ip_obj, d_port_obj, flags,
								annotation, enabled)
								values (
								'',
								$_pol_id,
								'$self->{_pol_seq}',
								'$self->{_action}',
								$_proto_obj_id,
								$_s_ip_obj_id,
								$_s_port_obj_id,
								$_d_ip_obj_id,
								$_d_port_obj_id,
								'$self->{_flags}',
								'$self->{_annotation}',
								'$self->{_enabled}'
		);";

		$dbi->do($sql) || croak ("couldn't commit rule $!");
	
		my $id = $dbi->last('policy_rules','id');
	
		$self->_debug("Rules commit success, ID was $id...");
	
		$self->{_id} = $id;

	}

        #Notify the Application Handler that it may need to re-apply some applications
        $apphandler->notifyApply($self);
        
	return ($self->{_id});

}

sub destroy {			#Remove yourself from database providing you are not listed anywhere

        my $self = shift;

        $self->_debug("Destroying rule in DB...");

	croak "Rule does not have ID specified" unless $self->{_id};

	my $sql = "delete from policy_rules where id='$self->{_id}';";

	my $result = eval { $dbi->do($sql); };

	unless ($result) {

		croak "Rule could not be deleted, has references";

	}

        #Notify the Application Handler that it may need to re-apply some applications
        $apphandler->notifyApply($self);

	return;

}

sub setSeq {			#Set sequence number of the rule

	my $self = shift;

	my $seq = shift;

        unless (($seq > 0) && ($seq < 65536)) {
                croak "Invalid Policy Sequence Number (must be between 1 and 65535)!";
        }
        my $polid = $self->{_pol_id}->getID;
        unless ($polid) {
                croak "Can't insert sequence number because we can't arbitrate (unaware of other rules) due to lack of parent policy id!!";
        }

	$self->_debug("Setting policy sequence number of rule to $seq");

        $self->{_pol_seq} = $seq;

}


1;
__END__

+------------+-----------------------+------+-----+---------+----------------+
| Field      | Type                  | Null | Key | Default | Extra          |
+------------+-----------------------+------+-----+---------+----------------+
| id         | int(20)               | NO   | PRI | NULL    | auto_increment | 
| pol_id     | int(10)               | NO   | MUL | NULL    |                | 
| pol_seq    | int(10)               | NO   | MUL | NULL    |                | 
| action     | enum('permit','deny') | NO   |     | deny    |                | 
| proto_obj  | int(10)               | YES  | MUL | NULL    |                | 
| s_ip_obj   | int(10)               | YES  | MUL | NULL    |                | 
| s_port_obj | int(10)               | YES  | MUL | NULL    |                | 
| d_ip_obj   | int(10)               | YES  | MUL | NULL    |                | 
| d_port_obj | int(10)               | YES  | MUL | NULL    |                | 
| flags      | varchar(10)           | YES  |     | NULL    |                | 
| annotation | text                  | YES  |     | NULL    |                | 
| enabled    | enum('1','0')         | NO   |     | 1       |                | 
+------------+-----------------------+------+-----+---------+----------------+

