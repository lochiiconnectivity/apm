#!/usr/bin/perl

package APM::Policy;

use APM::DBI;
use APM::AppHandler;
use APM::Policy::Rule;
use strict;
use Carp;
use Readonly;
use Data::Dumper;
use Scalar::Util 'blessed';



=pod

=head1 NAME

        APM::Policy

=head1 ABSTRACT

        Class to implement an Access Policy Manager Policy

=head1 SYNOPSIS

	use APM;
        use APM::Policy;

        #################
        # class methods #
        #################
        $apmPolicy    = APM::Policy->new      (                               #Initialise class

                                                debug => [0|1|2],       #Debug can be switched on, 1 is standard, 2 is with callstack
                                        	debugfile => $filename, #Debug can be sent to a file instead of STDOUT
                                        	debugstream => [0|1]    #Debug can be mirrored to a stream as well
                                                                	#Call getDebugStream to retrieve

						dbi => APM::DBI		#APM DBI object if you dont want to open a new DB connection

						apphandler => APM::AppHandler	#APM Application Handler object if you do not wish to 
										#Open a new one

						[id]		=>	[optional: overwrite an existing policy by ID]
						type		=>	APM Policy Object type as a string or id,
						name		=>	APM Policy name
						enabled		=>	APM Policy enabled state (1 or 0)


                                );

	$apmPolicy->load 			($id|$name)		#Returns a populated APM::Policy

	$apmPolicy->commit();			#Commits the policy change to the database, populates the policy ID

	$apmPolicy->destroy();			#Deletes the policy from the policy store

	$apmPolicy->reSeqRule			($seq_no,<before|after>,$seq_no);	#Resequences rules
											#Use -1 as second seq_no to indicate
											#The "Last" Rule


        #######################
        # object data methods #
        #######################


	$apmPolicy->getID();			#Retrieve the ID of a committed object
	$apmPolicy->getName();			#Retrieve the Name of an object
	$apmPolicy->getType();			#Retrieve the Type of an object
	$apmPolicy->getTypeS();			#Retrieve the Type of an object as a string
	$apmPolicy->getEnabled();		#Retrieve the Enabled of an object

	$apmPolicy->getRules();			#Retrieve a list (array) of APM::Policy::Rule objects which are part of this policy

	$apmPolicy->getRulesA([$optim]);	#Get rules as an ACL, provide optional value "$optim" to state that small RANGE
						#operators are unrolled (where range of 10 or less ports), this optimises LOU
						#consumption in Cisco TCAM environments where the eq operator carries no
						#LOU penalty but the range operator consumes two LOU registers (start, end)
						#and hence a complete LOU


	######################
	# object properties  #
	######################

	These properties are READ ONLY

	_id	= Policy ID
	_type	= Policy Type
	_s_type	= Policy Type as a string
	_name	= Policy Name
	_enabled = Policy enabled state
	


=head1 DESCRIPTION
	
	APM::Policy implements an interface to the APM Policy, here is an example

	my $apmPolicy = APM::Policy->new( 

						Name=>'Policy to permit access to the Secure WAN',
						Type => 'IPV4_ADDR',

					);

	my $id = $apmPolicy->commit();

	my $newApmPolicy = $apmPolicy->load($id);

	use Data::Dumper;

	print Dumper($apmPolicy); print "\n";
	print Dumper($newApmPolicy); print "\n";


We advise you to create policies using the APM interface (newPolicy)


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
	_type 			=> undef,
	_name			=> undef,
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

 if ($this->{in_type}) {
        my ($t_type,$s_type) =  $this->_validatetype($this->{in_type});
        Readonly $this->{_type} => $t_type;
        Readonly $this->{_s_type} => $s_type;
 }
 if ($this->{in_name}) {
	my $name = $this->_validatename($this->{in_name});
	Readonly $this->{_name} => $name;
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

sub _validatename {
        my $self = shift;
        my $name = shift;
	if ($name=~m/[a-zA-Z0-9_]/) {
		return ($name);
	}
	else {
		croak "Name contains invalid characters!";
	}
}

sub _validatetype {

        my $self = shift;
        my $type = shift;
        my $typeid;

        $self->_debug("Validating type $type");

        croak "No type to validate" unless ($type);

        if ($type =~m/^(\d+)$/) {
		unless (($typesbyid->{$1} eq 'IPV4_ADDR') || ($typesbyid->{$1} eq 'IPV6_ADDR')) {
			croak "Only IPV4_ADDR or IPV6_ADDR may be used as policy types";
		}
                $self->_debug("Validated: returning type numeric type $1, string type $typesbyid->{$1}");
                return ($1,$typesbyid->{$1});
        }
        elsif ($type =~m/(\w+)/) {
		unless (($type eq 'IPV4_ADDR') || ($type eq 'IPV6_ADDR')) {
			croak "Only IPV4_ADDR or IPV6_ADDR may be used as policy types";
		}
                $self->_debug("Validated: returning type numeric type $types->{$1}, string type $1");
                return ($types->{$1},$1);
        }
        else {
                croak "Unknown object type $type";
        }

}

sub _getMaxSeq {		#Get maximum sequence number from policy_rules

	my $self = shift;

	my $sql = "select max(pol_seq) as max_seq from policy_rules where pol_id='$self->{_id}';";

	my $results = $dbi->query($sql);

	unless ($$results[0]) {
		croak "Can't get max_seq from policy!";
	}

	return ($$results[0]->{max_seq});

}


sub getID {			#Retrieve ID
	my $self = shift;
	return ($self->{_id});
}

sub getName {			#Retrieve Name
	my $self = shift;
	return ($self->{_name});
}

sub getType {			#Retrieve Type
	my $self = shift;
	return ($self->{_type});
}

sub getTypeS {			#Retrieve Type as a string
	my $self = shift;
	return ($self->{_s_type});
}

sub getEnabled {		#Retrieve enabled
	my $self = shift;
	return ($self->{_enabled});
}

sub getRules {			#Retrieve rules
	my $self = shift;
	
	my $sql = "select id from policy_rules where pol_id = '$self->{_id}';";

	my $results = $dbi->query($sql);

	my @rules;

	my %ruldata;
        $ruldata{debug} = $self->{_debug};
        $ruldata{debugfile} = $self->{_debugfile};
        $ruldata{debugstream} = $self->{_debugstream};
        $ruldata{dbi} = $dbi;


	if ($$results[0]) {
		foreach my $rulerow (@{$results}) {
			my $ruleid = $rulerow->{id};
			my $rule = APM::Policy::Rule->new(%ruldata) || croak "Can't create new APM::Policy::Rule !";
			$self->_debug("GetRules -> Loading in Rule $ruleid...\n");
			$rule->load ($ruleid);
			$self->_debug("GetRules -> Loaded  Rule $rule->{_id} Seq $rule->{_pol_seq} Annotation $rule->{_annotation}");
			push (@rules,$rule);
		}
	}

	return(\@rules);
}

sub getRulesA {			#Retrieve rules as an acl

	my $self = shift;
	my $louoptim = shift;

	my $acl;
	my $printseqoffset;

	my $rules = $self->getRules;

	my %newrules;

	#Sort into sequence order
	foreach my $rule (@{$rules}) {
		next unless ($rule->getEnabled == 1);
		my $polseq = $rule->getPolSeq;
 		$newrules{$rule->getPolSeq} = $rule;
	}

	foreach my $seq (sort {$a <=> $b} keys %newrules) {

		my $rule = $newrules{$seq};

		next unless ($rule->getEnabled == 1);

		my $rptype	= $self->getTypeS;

		my $printseq 	= $rule->getPolSeq;			#Decouple printed sequence from actual
		$printseq      += $printseqoffset;			#Decouple printed sequence from actual
		if ($rptype eq 'IPV6_ADDR') {
			$printseq = "sequence $printseq";
		}

		my $rulid	= $rule->getID;
		my $rpid	= $self->getID;
		my $action 	= $rule->getAction;
		my $sipobj	= eval{$rule->getSIPObj->getValueA} 		||	"any";
		my $dipobj	= eval{$rule->getDIPObj->getValueA}		||	"any";
		my $annotation	= $rule->getAnnotation;
		my $flags	= $rule->getFlags;

                my ($proto,$sport,$dport);
                eval { $proto   = lc($rule->getProtoObj->getValueA)     		};
		unless ($proto) {
			if    ($rptype eq 'IPV4_ADDR') {	$proto = 'ip';		}
			elsif ($rptype eq 'IPV6_ADDR') {	$proto = 'ipv6';	}
			else{$self->_debug("Unknown type $rptype when proto udef");next;};
		}
                eval { $sport   = $rule->getSPortObj->getValueA;                        };
                eval { $dport   = $rule->getDPortObj->getValueA;                        };

		#Hack for ICMP TYPECODE 
		$dport =~ s/999999999/0/g;


		#LOU optimisations for Cisco TCAM based platforms may be performed here
		#If the user wants
		if ($louoptim) {
                        if (($sport =~m/range/) && ($dport =~m/range/)) {       #Don't perform any optimisation if both
                                                                                #source and destinations are ranges, potential
                                                                                #unrolling could be too big
                                                                                #
                                $acl .= "remark APM:P:$rpid:R:$rulid $annotation\n";
                                $acl .= "$printseq $action $proto $sipobj $sport $dipobj $dport $flags\n";
                        }
			elsif ($sport =~ m/range (\d+) (\d+)/) {		#Source contains a range which may need 
										#Optimising
				my $rangestart = $1;
				my $rangeend = $2;
				if ($rangeend - $rangestart <= 10) {		#Only perform optimisation if range
										#is of up to 10 ports

					$acl .= "remark APM:P:$rpid:R:$rulid $annotation (optimised)\n";
					my $port;
					for ($port = $rangestart;$port < ($rangeend + 1);$port++) {
						$acl .= "$printseq $action $proto $sipobj eq $port $dipobj $dport $flags\n";
						$printseq++;		#Dont panic, this will get reset when we hit the next rule
						$printseqoffset++;	#Hence we store the offset so it doesn't get completely trashed!
					}

				}
				else {
					$acl .= "remark APM:P:$rpid:R:$rulid $annotation\n";
					$acl .= "$printseq $action $proto $sipobj $sport $dipobj $dport $flags\n";
				}
			}
			elsif ($dport =~ m/range (\d+) (\d+)/) {		#Destination contains a range which may need
										#Optimising
				my $rangestart = $1;
				my $rangeend = $2;
				if ($rangeend - $rangestart <= 10) {		#Only perform optimisation if range
										#is of up to 10 ports

					$acl .= "remark APM:P:$rpid:R:$rulid $annotation (optimised)\n";
					my $port;
					for ($port = $rangestart;$port < ($rangeend + 1);$port++) {
						$acl .= "$printseq $action $proto $sipobj $sport $dipobj eq $port\n";
						$printseq++;		#Dont panic, this will get reset when we hit the next rule
						$printseqoffset++;	#Hence we store the offset so it doesn't get completely trashed!
					}

				}
				else {
					$acl .= "remark APM:P:$rpid:R:$rulid $annotation\n";
					$acl .= "$printseq $action $proto $sipobj $sport $dipobj $dport $flags\n";
				}
			}
			else {
				$acl .= "remark APM:P:$rpid:R:$rulid $annotation\n";
				$acl .= "$printseq $action $proto $sipobj $sport $dipobj $dport $flags\n";
			}

		}
		else {
			$acl .= "remark APM:P:$rpid:R:$rulid $annotation\n";
			$acl .= "$printseq $action $proto $sipobj $sport $dipobj $dport $flags\n";
		}
		

	}

	return ($acl);

}

sub load   {			#Load from database

	my $self = shift;

	my $in = shift;
	my $sql;

        if ($in=~m/^\d+/) {
                $self->_debug("loading policy with ID $in");
                $sql = "select * from policies where id='$in';";
        }
        else {
                $self->_debug("loading policy with name $in");
                $sql = "select * from policies where name='$in';";
        }



	$self->_debug("loading policy $in");


	my $results = $dbi->query($sql);

	unless ($$results[0]) {
		croak "Policy $in not found in policy store";
	}
	else {
		Readonly $self->{_id} 			=> $$results[0]->{id};
		Readonly $self->{_type} 		=> $$results[0]->{type};
		Readonly $self->{_s_type} 		=> $typesbyid->{$$results[0]->{type}};
		Readonly $self->{_name} 		=> $$results[0]->{name};
		Readonly $self->{_enabled} 		=> $$results[0]->{enabled};
	}

	return 1;


}

sub commit {			#Commit to database, return ID on success

	my $self = shift;

	$self->_debug("Committing policy to DB...");

	#Dont allow bad commits
	croak "Policy must have a type " unless $self->{_type};
	croak "Policy must be named " unless $self->{_name};

	$self->{_enabled} = 1 unless (defined($self->{_enabled}));

	my $sql;
	my $id;

	if ($self->{_id}) {

		#If the policy already exists, we need to check that the user has not changed the type, 
		#if he/she has then we must delete all the rules since they can no longer apply to this policy
		#
		$self->_debug("Checking if any rules depend on this policy...");
		my $checksql = "select policies.type,policy_rules.id as rid from policies left join policy_rules on (policies.id = policy_rules.pol_id) where policies.id = '$self->{_id}' and policy_rules.id is not null;";
		my $checkresults = $dbi->query($checksql);
		if ($$checkresults[0]) {
			$self->_debug("Some do, checking if the type of policy has changed...");
			unless ($$checkresults[0]->{type} == $self->{_type}) {
				$self->_debug("The type of policy has changed, deleting the rules...");
				my $killsql = "delete from policy_rules where pol_id='$self->{_id}';";
				$dbi->do($killsql);
			}
		}

                $sql = "update policies set 
                                                type            =       '$self->{_type}',
                                                name            =       '$self->{_name}',
                                                enabled         =       '$self->{_enabled}'
                                         where id = '$self->{_id}';
                ";

                my $id = $self->{_id};

                $dbi->do($sql) || croak ("couldn't commit policy $!");

                $self->_debug("Policy commit success, ID was $id...");

	}

	else {

		$sql = "insert into policies (id, type, name, enabled) values ('$self->{_id}','$self->{_type}','$self->{_name}','$self->{_enabled}');";
	
		$dbi->do($sql) || croak ("couldn't commit policy $!");
	
		my $id = $dbi->last('policies','id');
	
		$self->_debug("Policy commit success, ID was $id...");
	
		$self->{_id} = $id;

	}

        #Notify the Application Handler that it may need to re-apply some applications
        $apphandler->notifyApply($self);
        
	return ($self->{_id});

}

sub destroy {			#Remove yourself from database providing you are not listed anywhere

        my $self = shift;

        $self->_debug("Destroying policy in DB...");

	croak "Policy does not have ID specified" unless $self->{_id};

	#delete all the rules first so that the policy is no longer referenced
	my $rsql = "delete from policy_rules where pol_id = '$self->{_id}';";
	my $rresult = eval { $dbi->do($rsql) };

	#First, try and delete the policy, it will fail if it is referenced anywhere
	my $sql = "delete from policies where id='$self->{_id}';";

	my $result = eval { $dbi->do($sql); };

	unless ($result) {

		croak "Policy could not be deleted, has references";

	}


	#Application handler does not need to be notified because we can't destroy any policies
	#referenced by any applications due to DB constraint

	return;

}

sub reSeqRule {			#Resequence rule

	my $self = shift;

	my ($rule_to_move_seq,$seq_action,$rule_to_move_around_seq) = @_;

	if ($rule_to_move_around_seq == -1) {				#Using -1 as rule_to_move_around_seq should mean
									#"Last Rule"
		$rule_to_move_around_seq = $self->_getMaxSeq;

	}

	unless (
		($rule_to_move_seq > 0) && ($rule_to_move_seq < 65536) &&
		($rule_to_move_around_seq > 0) && ($rule_to_move_around_seq < 65536)
	) {
		croak "Invalid policy rule sequence numbers ($rule_to_move_seq,$rule_to_move_around_seq), must be between 1 and 65535!";
	}

	unless (($seq_action eq 'before') || ($seq_action eq 'after')) {
		croak "Invalid policy rule action ($seq_action), must be 'before' or 'after'";
	}

	if ($rule_to_move_seq == $rule_to_move_around_seq) {
		croak "Invalid : you must specify DIFFERENT sequence numbers!";
	}

	$self->_debug ("Resequencing rule with seq $rule_to_move_seq $seq_action rule with seq $rule_to_move_around_seq");

	my $rules = $self->getRules;

	my $found_rule_to_move_seq;
	my $found_rule_to_move_around_seq;
	my $rule_to_move;

	foreach my $rule (@{$rules}) {

		if ($rule->getPolSeq() == $rule_to_move_seq) {
			$found_rule_to_move_seq = 1;
			$rule_to_move = $rule;
		}
		if ($rule->getPolSeq() == $rule_to_move_around_seq) {
			$found_rule_to_move_around_seq = 1;
		}
	}

	unless ($found_rule_to_move_seq) {
		croak "Rule seq $rule_to_move_seq not found in policy!";
	}
	unless ($found_rule_to_move_around_seq) {
		croak "Rule seq $rule_to_move_around_seq not found in policy!";
	}

	#Now, the nitty gritty...
	#E ID  PID SEQ  ACTION   PROTO           SIO             SPO     DIO     DPO             ANNOTATION
	#- --- --- ---  ------   ------------    -----------     -----   -----   -----------     -------------------
	#1 2   1   1    permit   ANY             host1           ANY     host2   ANY             Example Rule #1
	#1 4   1   2    permit   UDP             host1           port1   host2   port2           Example Rule #3
	#1 3   1   3    permit   TCP             host1           port1   host2   port2           Example Rule #2
	#1 5   1   4    permit   UDP             host2           port1   host1   port2           Example Rule #4
	#
	#
	my $bumpa;		#Need to bump everybody up at once

	my %restripehash;	#Needed for restriping

	foreach my $rule (@{$rules}) {
		
		my $curPolSeq = $rule->getPolSeq();

		next if ($curPolSeq == $rule_to_move_seq);

		if (($curPolSeq >= $rule_to_move_around_seq) && ($seq_action eq 'before')) {
			$self->_debug( "checking if curpolseq $curPolSeq >= $rule_to_move_around_seq (rule to move)...");
			my $polseq = $curPolSeq;
			$polseq++;
			$self->_debug( "Bumping Seq $curPolSeq up to $polseq");
			$rule->setSeq($polseq);	#Bump up the movearound and upwards
			$restripehash{$polseq} = $rule;
		}
		elsif (($curPolSeq <= $rule_to_move_around_seq) && ($seq_action eq 'after')) {
			$self->_debug( "checking if curpolseq $curPolSeq <= $rule_to_move_around_seq (rule to move)...");
			my $polseq = $curPolSeq;

			#If we have to decrement seq 1, we need to bump everybody up 
			if ($bumpa == 1) {
				$curPolSeq++;
			}
			if ($polseq == 1) {
				$self->_debug("Bumping Seq 1 up to 2 and setting BUMPA (because it is the first)");
				$curPolSeq++;
				$polseq++;
				$bumpa = 1;
			}
			
			$polseq--;
			$self->_debug("Bumping Seq $curPolSeq down to $polseq\n");
			$rule->setSeq($polseq); #Bump down the movearound and downwards 
			$restripehash{$polseq} = $rule;

		}
		else {
			$restripehash{$curPolSeq} = $rule;
		}
	}

	if ($bumpa) {
		$rule_to_move_around_seq++;	#This must also move up if BUMPA is set
	}
	$rule_to_move->setSeq($rule_to_move_around_seq);	#Renumber the rule we are moving into the movearound position (which has been bumped up)
	$restripehash{$rule_to_move_around_seq} = $rule_to_move;

	#Now restripe all the rules by sequence number
	#
	$self->_debug("Restriping all rules in policy now...");

	my $restripecounter = 1;

	foreach my $seq (sort keys %restripehash) {
		$restripehash{$seq}->setSeq($restripecounter);
		$restripehash{$seq}->commit();
		$restripecounter++;
	}


}


1;
__END__

