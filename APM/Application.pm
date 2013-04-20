#!/usr/bin/perl
#


package APM::Application;

use APM::DBI;
use strict;
use Carp;
use Readonly;
use Data::Dumper;
use Scalar::Util 'blessed';



=pod

=head1 NAME

        APM::Application

=head1 ABSTRACT

        Class to implement an Access Policy Manager Policy Application

=head1 SYNOPSIS

	use APM;
        use APM::Application;

        #################
        # class methods #
        #################
        $apmApp    = APM::Application->new      (                               #Initialise class

                                                debug => [0|1|2],       #Debug can be switched on, 1 is standard, 2 is with callstack
                                        	debugfile => $filename, #Debug can be sent to a file instead of STDOUT
                                        	debugstream => [0|1]    #Debug can be mirrored to a stream as well
                                                                	#Call getDebugStream to retrieve

						dbi => APM::DBI		#APM DBI object if you dont want to open a new DB connection

						[id]		=>	[optional: overwrite an existing application by ID]
						pol_id		=>	APM Policy Object to be applied
						router		=>	Name of RANCID router to apply policy to
						interface	=>	Name of RANCID router interface to apply policy to
						direction	=>	Direction to apply to [in|out]
						enabled		=>	APM Policy Application enabled state (1 or 0)


                                );

	$apmApp->load				$id			#Returns a populated APM::Application

	$apmApp->commit;			#Commits the application change to the database, populates the application ID

	$apmApp->destroy();			#Deletes the application from the application store

	$apmApp->apply([$jdi]);			#Apply changes, reset the needapply flag in the process
						#Set JDI flag to be dumb (internal use only) - does not clean up after itself

	$apmApp->unapply([$jdi]);		#unApply changes, do not reset the needapply flag in the process
						#Set JDI flag to be dumb (internal use only) - does not clean up after itself

	$apmApp->setNeedApply($state);		#Sets the state of the needapply flag ([0|1|2|3|4])
						#Needapply flag decoder is as follows:
						#nb: JDI is an old term for "Just do it" and don't ask questions
						#
						#0 or NULL = Do nothing
						#1 = Standard application (apply with policies)
						#2 = Standard unapplication (clean up after yourself)
						#3 = Apply to interface only (Apply JDI)
						#4 = Unapply from interface only (Unapply JDI)
						#5 = Apply to interface only and Do NOT set applied bit  (internal use only)


        #######################
        # object data methods #
        #######################


	$apmApp->getID();			#Retrieve the ID of a committed object
	$apmApp->getPolID();			#Retrive the APM Policy object associated with the application
	$apmApp->getRouter();			#Retrieve the Router 
	$apmApp->getInterface();		#Retrieve the Router Interface
	$apmApp->getDirection();		#Retrieve the Direction
	$apmApp->getEnabled();			#Retrieve the Enabled of an object
	$apmApp->getNeedApply();		#Retrieve the State of the NeedApply Flag


	######################
	# object properties  #
	######################

	These properties are READ ONLY

	_id		= Application ID
	_pol_id		= Policy ID
	_router 	= Router
	_interface 	= Router Interface
	_direction	= Direction
	_enabled 	= App enabled state

	These properties are READ WRITE but DO NOT MODIFY
	
	_needapply	= Application needs to be applied

=head1 DESCRIPTION

	APM::Application implements an interface to the APM Policy Application, here is an example:

	my $apmApp = APM::Application->new(
						pol_id=>$apmpolicy,
						router=>'core1',
						interface=>'FastEthernet1/0',
						direction=>'in',
						enabled=>1,
					);

	my $id = $apmApp->commit();

	my $newApmApp = $apmApp->load($id);

	use Data::Dumper;

	print Dumper($apmApp); print "\n";
	print Dumper($newApmApp); print "\n";


We advise you to create applications using the APM interface (newApplication)


=head1 TODO

        Tidy POD

=cut


my $dbi;
my $types;
my $typesbyid;


sub new
{
 my $proto = shift;
 my $class = ref $proto || $proto;

 my $this = {

	_id 			=> undef,
	_pol_id 		=> undef,
	_router 		=> undef,
	_interface		=> undef,
	_direction		=> undef,
	_enabled		=> undef,
	_needapply		=> 0,

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

 if ($this->{in_router}) {
        Readonly $this->{_router} => $this->{in_router};
 }
 if ($this->{in_interface}) {
	$this->_validateinterface($this->{in_interface});
        Readonly $this->{_interface} => $this->{in_interface};
 }
 if ($this->{in_direction}) {
	unless (($this->{in_direction} eq 'in') || ($this->{in_direction} eq 'out')) {
		croak "Direction must be in or out";
	}
        Readonly $this->{_direction} => $this->{in_direction};
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
        if ($self->{'_debug'} == 2) {	#Callstack debug

	        my $maxcalldepth = 8;	#Maximum call depth we will trace to
		my $calls;		#Iterator
		my $callstack;		#Call stack
		my $tabstack;		#Tab stack
		for ($calls = $maxcalldepth; $calls > 0; $calls--) {
			my $stackptr = (caller($calls))[3];
			$callstack.="$stackptr\/" if ($stackptr);
		}; chop($callstack);
	        $msg = "$callstack(): $msg";

	}
	else {				#Standard caller debug
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


sub _validateinterface {	#Validate interface names

	my $self = shift;
	my $interface = shift;

	unless ($interface=~ m/Serial\d|FastEthernet\d|GigabitEthernet\d|TenGigabitEthernet\d|ATM\d|Multilink\d|Dialer\d|Virtual-Template\d|MFR\d|^line/) {
			croak "Invalid interface name ($interface) (Interfaces are CASE sensitive, e.g Serial and FastEthernet";
		};
}

sub _isaclpresent	{	#See if ACL is present on the router or not according to our DB
				#Logic is to check if the policy is applied to another application
				#Other than ourselves
				#Returns the number of times the ACL was present 

	my $self = shift;
	my $id = $self->{_id};
	my $pol_id = $self->{_pol_id}->getID;
	my $router = $self->{_router};
	my $sql = "select * from applications where router = '$router' and pol_id = '$pol_id' and enabled = 1;";
	my $results = $dbi->query($sql);
	if ($$results[0]) {
		my $resultcount = $#{$results};
		$resultcount++;	#(remember, arrays start at 0)
		$self->_debug("This ACL is present on the router ($resultcount times)");
		return $resultcount;
	}
	else {
		$self->_debug("This ACL is NOT present on the router");
		return;
	}

}

sub _isaclneeded	{	#See if ACL is needed at all, for instance, removing its last application 
				#On the router means it is no longer needed
				#This is the same as _isaclpresent so we wrap it but is used for readability

	my $self = shift;
	my $aclpresent = $self->_isaclpresent;
	
	if ($aclpresent > 1) {
		$self->_debug("This ACL is NEEDED on the router");
		return 1;	#Return that ACL is needed
	}
	elsif ($aclpresent) {
		$self->_debug("This ACL is NOT NEEDED on the router");
		return;		#Return that ACL is NOT needed
	}
	else {
		$self->_debug("This ACL is NOT NEEDED on the router because it was NEVER THERE");
		return;		#Return that ACL is NOT needed
	}
	
}

sub _getpolicyrouterapps	{	#Get a list of all applications which use policy POLID on router ROUTER and return them

	my $self = shift;
	my $polid = shift;
	my $router = shift;

	my @returnapps;

	return unless ($polid && $router);

	my $sql = "select * from applications where pol_id = $polid and router = '$router' and needapply != 1;";
	my $results = $dbi->query($sql);

	if ($$results[0]) {
		foreach my $result (@{$results}) {
			my $app = APM::Application->new(
                                                debug           =>      $self->{_debug},
                                                debugfile       =>      $self->{_debugfile},
                                                debugstream     =>      $self->{_debugstream},
                                                dbi             =>      $dbi,
			);
			$app->load($result->{id});
			push (@returnapps,$app);
		}
		return (\@returnapps);
	}
	else {
		return;
	}

}

sub _getacldirectives {		#Retrieve correct ACL directives for address family

	my $self = shift;
	my $interface = shift;
	my $aclname = shift;
	my $policyid = shift;
	my $policytype = shift;

	my $aclapplydirective;
	my $emptyaclrules;

	my $isline = ($interface=~m/^line /) ? 1 : undef;	#line acls need to be applied differently
	my $aclinterface = $isline ? $interface : "interface $interface";
	my $aclname = "APM:$policyid:$aclname";
	
	if ($policytype eq 'IPV4_ADDR') {
	        $aclapplydirective = $isline ? "access-class" : "ip access-group";
		$emptyaclrules = "remark APM:P:$policyid:R:0 EMPTY ACL\n";
		$emptyaclrules .= "1 permit ip any any";
	}
	elsif ($policytype eq 'IPV6_ADDR') {
	        $aclapplydirective = $isline ? "ipv6 access-class" : "ipv6 traffic-filter";
		$emptyaclrules = "remark APM:P:$policyid:R:0 EMPTY ACL\n";
		$emptyaclrules .= "1 permit ipv6 any any";
	}
	elsif ($policytype) {
	        croak "Internal error: policy type $policytype found and not expected";
	}
	else {
	        croak "Internal error: policy type not provided, bailing";
	}

	return ($aclinterface,$aclname,$aclapplydirective,$emptyaclrules);

}

sub getID {			#Retrieve ID
	my $self = shift;
	return ($self->{_id});
}

sub getPolID {			#Retrieve Policy ID
	my $self = shift;
	return ($self->{_pol_id});
}

sub getRouter {			#Retrieve router
	my $self = shift;
	return ($self->{_router});
}

sub getInterface {		#Retrieve router interface
	my $self = shift;
	return ($self->{_interface});
}

sub getDirection {		#Retrieve direction
	my $self = shift;
	return ($self->{_direction});
}

sub getEnabled {                #Retrieve Enabled
        my $self = shift;
        return ($self->{_enabled});
}

sub getNeedApply {                #Retrieve Need to apply
        my $self = shift;
        return ($self->{_needapply});
}



sub load   {			#Load from database

	my $self = shift;

	my $in = shift;
	my $sql;

        $self->_debug("loading application with ID $in");
        $sql = "select * from applications where id='$in';";

	$self->_debug("loading application $in");

	my $results = $dbi->query($sql);

	unless ($$results[0]) {
		croak "Application $in not found in application store";
	}
	else {
 		my $pol_id      =  APM::Policy->new; $pol_id            ->      load($$results[0]->{pol_id});
		Readonly $self->{_id} 			=> $$results[0]->{id};
		Readonly $self->{_pol_id} 		=> $pol_id;
		Readonly $self->{_router} 		=> $$results[0]->{router};
		Readonly $self->{_interface} 		=> $$results[0]->{interface};
		Readonly $self->{_direction} 		=> $$results[0]->{direction};
		Readonly $self->{_enabled} 		=> $$results[0]->{enabled};
		$self->{_needapply}			=  $$results[0]->{needapply};
	}

	return 1;


}

sub commit {			#Commit to database, return ID on success

	my $self = shift;

	$self->_debug("Committing application to DB...");

	#Dont allow bad commits
	croak "Application must have a policy id" unless ($self->{_pol_id});
	my $pol_id = $self->{_pol_id}->getID;
	croak "Application must have a router" unless ($self->{_router});
	croak "Application must have a router interface" unless ($self->{_interface});
	croak "Application must have a router interface direction" unless ($self->{_direction});

	#ENFORCE APPLICATION INTERFACE CONSTRAINT
	#We can't do this in the database, basically, we want to check that an existing 
	#application for this router, interface and direction does not already exist 
	#unless the policy type is different.
	my $ccptype = $self->{_pol_id}->getType;
	my $ccsql = "select a.router,a.interface,a.direction,p.type from applications a left join policies p on (a.pol_id = p.id) where a.router='$self->{_router}' and a.interface='$self->{_interface}' and a.direction='$self->{_direction}' and p.type='$ccptype';";
	my $ccresults = $dbi->query($ccsql);
	if    ($$ccresults[1])	{	#Uh oh, multiple values, somebody has been screwing with the DB or we are out of sync!!!!
		croak "Internal Error: Database is corrupt or out of sync, the app/router/intf/direct/type constraint has been violated, we can not continue";
	}
	elsif ($$ccresults[0]) 	{	#Type already exists, do not allow dupes but check if it is really a dupe first
		croak "Sorry can not add another application for this policy here, there is already a policy of the same type applied on the router's interface in the direction in question!" unless ($self->{_id});	#If ID exists we are editing an existing ID so we can continue
	}
		

	$self->{_enabled} = 1 unless (defined($self->{_enabled}));

	my $sql;
	my $id;
	my $needapply;

	if ($self->{_enabled} == 1) {		#If we are not disabled, we need to be applied
		#Determine what type of apply is needed, if there are EXISTING ENABLED policies which do NOT NEED APPLY
		#for the SAME POL_ID and for the SAME ROUTER then we will set the state to three (incremental interface only)
		#and 1 if else (full apply)
		my $sql = "select * from applications where pol_id='$pol_id' and router='$self->{_router}' and enabled=1 and needapply='0';";
		my $results = $dbi->query($sql);
		if ($$results[0]) {
			$self->_debug("We have found other APPLIED ENABLED applications with POL_ID $pol_id on $self->{_router} so this apply will be INCREMENTAL OK???");
			$needapply = 3;
		}
		else {
			$self->_debug("We did not find other APPLIED ENABLED applications with POL_ID $pol_id on $self->{_router} so this apply will be FULL OK???");
			$needapply = 1;
		}
	}
	else {					#If we are disabled, we need to be unapplied
		$needapply = 0;
		$self->unapply();
	}

	if ($self->{_id}) {

                $sql = "update applications set 
						pol_id		=	'$pol_id',
						router		=	'$self->{_router}',
						interface	=	'$self->{_interface}',
						direction	=	'$self->{_direction}',
						needapply	=	$needapply,
                                                enabled         =       '$self->{_enabled}'
                                         where id = '$self->{_id}';
                ";

                my $id = $self->{_id};

                $dbi->do($sql) || croak ("couldn't commit application $!");

                $self->_debug("Application commit success, ID was $id...");

	}

	else {

		$sql = "insert into applications values ('$self->{_id}','$pol_id','$self->{_router}','$self->{_interface}','$self->{_direction}','$needapply','$self->{_enabled}');";
	
		$dbi->do($sql) || croak ("couldn't commit application $!");
	
		my $id = $dbi->last('applications','id');
	
		$self->_debug("Policy commit success, ID was $id...");
	
		$self->{_id} = $id;

	}



	return ($self->{_id});

}

sub destroy {			#Remove yourself from database providing you are not listed anywhere

        my $self = shift;

        $self->_debug("Destroying application in DB...");

	croak "Application does not have ID specified" unless $self->{_id};

	#Do this as a transaction, if we fail here then don't actually unapply the object
	#TODO: may cause bug if we don't complete here and leave AC off
	$dbi->begin;

	#Then unapply straight away before we lose the data, use applystate 2 which allows us
	#to tidy up after ourselves (as opposed to applystate 4 which is just quick and dirty)
	$self->unapply(2);

	my $sql = "delete from applications where id='$self->{_id}';";

	my $result = eval { $dbi->do($sql); };

	unless ($result) {
		croak "Application could not be deleted";
	}

	$result = $dbi->commit;

	unless ($result) {
		croak "Internal Error: Application could not be deleted"; # YOU SHOULD NEVER SEE THIS PLEASE REPORT IT
	}

	return 1;

}

sub _spoolcmd {		#Spool an IOS CMD 

	my $self = shift;
	my $cmds = shift;
	my $router = shift;
	my $cmd = shift;

	$self->_debug ("SPOOL ROUTER: $router, CMD: $cmd");

	push (@{$cmds->{$router}},$cmd);

	return;

}

sub _spoolmerge {

	my $self = shift;
	my $cmds = shift;
	my $incmds = shift;
	foreach my $key (sort keys %{$incmds}) {
		foreach my $cmd (@{$incmds->{$key}}) {
			push (@{$cmds->{$key}},$cmd);
		}
	}
}

sub apply {

	my $self = shift;

	my $applystate = shift;

	my %cmds;

	my $pol_id = $self->{_pol_id}->getID;
	my $router = $self->{_router};
	my $interface = $self->{_interface};
	my $direction = $self->{_direction};

	#Get the type of ACL and use it to set the command style
	my ($aclinterface,$aclname,$aclapplydirective,$emptyaclrules) = $self->_getacldirectives($self->{_interface},$self->{_pol_id}->getName,$self->{_pol_id}->getID,$self->{_pol_id}->getTypeS);

	$self->_debug ("APPLY Application $self->{_id} AS=$applystate");

	my $aclpresent = $self->_isaclpresent;

	if ($aclpresent && ($applystate != 3 && $applystate != 5)) {	#If ACL is present, we still need to apply it in case it has changed
						#We do this by first UNApplying all instances of the ACL before we change it
						#As not to be disruptive
				
		$self->_debug ("Start by UNApplying all dependant applications for safety");
		my $appstounapply = $self->_getpolicyrouterapps($pol_id,$router);

		if ($$appstounapply[0]) {
			foreach my $apptounapply (@{$appstounapply}) {
				my $appid = $apptounapply->getID;
				my $router = $apptounapply->getRouter;
				$self->_debug ("UNApplying app $appid on router $router for safety");
				$self->_spoolmerge(\%cmds,$apptounapply->unapply(4));
			}
		}
		else {
			$self->_debug ("No dependant applications");
		}


		$self->_debug ("ACL $aclname is present on router, we will be changing it");

		$self->_spoolcmd(\%cmds,$router,"no access-list extended $aclname");

		$self->_spoolcmd(\%cmds,$router,"access-list extended $aclname");

		my $acl = $self->{_pol_id}->getRulesA;

		$acl = $emptyaclrules unless ($acl);	#Ensure all empty policies are furnished with a permit if nothing else

		foreach my $aclline (split(/\n/,$acl)) { $self->_spoolcmd(\%cmds,$router,$aclline); };

		$self->_spoolcmd(\%cmds,$router,"exit");

		$self->_debug ("Now Re-Apply all those that we un-applied");

		if ($$appstounapply[0]) {
			foreach my $apptounapply (@{$appstounapply}) {
				my $appid = $apptounapply->getID;
				my $router = $apptounapply->getRouter;
				$self->_debug ("REApplying app $appid on router $router after unapply");
				$self->_spoolmerge(\%cmds,$apptounapply->apply(5));
				#Any applications which have been re-applied need to have their needApply bit set to off
				#Because this operation "kills two birds with one stone" when you have a queue of apps
				#waiting for apply, it will deal with them all in one fell swoop, but their needApply bits
				#will remain set to on which is annoying and will be dealt with here.
				$apptounapply->setNeedApply(0);
			}
		}
		else {
                        $self->_debug ("No dependant applications, just applying");
			$self->_spoolcmd(\%cmds,$router,$aclinterface);
			$self->_spoolcmd(\%cmds,$router,"$aclapplydirective $aclname $direction");
			$self->_spoolcmd(\%cmds,$router,"exit");
                }

	}
	elsif (!$aclpresent && ($applystate != 3 && $applystate != 5)) {

		$self->_debug ("ACL $aclname is not present on router, we will install it and apply");
		$self->_spoolcmd(\%cmds,$router,"access-list extended $aclname");
		my $acl = $self->{_pol_id}->getRulesA;
		foreach my $aclline (split(/\n/,$acl)) { $self->_spoolcmd(\%cmds,$router,$aclline); };
		$self->_spoolcmd(\%cmds,$router,"exit");
		$self->_spoolcmd(\%cmds,$router,$aclinterface);
		$self->_spoolcmd(\%cmds,$router,"$aclapplydirective $aclname $direction");
		$self->_spoolcmd(\%cmds,$router,"exit");
	}
	elsif ($applystate == 3) {	#External quick remove
		$self->_debug ("We have just been asked to apply, we will, and we will be using main cmd array");
		$self->_spoolcmd(\%cmds,$router,$aclinterface);
                $self->_spoolcmd(\%cmds,$router,"$aclapplydirective $aclname $direction");
                $self->_spoolcmd(\%cmds,$router,"exit");
	}
	elsif ($applystate == 5) {
		$self->_debug ("We have just been asked to apply, we will, we will not be using main cmd array");
		my %cmds;
		$self->_spoolcmd(\%cmds,$router,$aclinterface);
		$self->_spoolcmd(\%cmds,$router,"$aclapplydirective $aclname $direction");
		$self->_spoolcmd(\%cmds,$router,"exit");
		return (\%cmds);
	}

        foreach my $router (sort keys %cmds) {
                print "ROUTER: $router\n";
                print "conf t\n";
                foreach my $cmd (@{$cmds{$router}}) {
                        print "$cmd\n";
                }
                print "end\n";
        }

	$self->setNeedApply(0) unless ($applystate == 5);
}

sub unapply {			#UNAPPLY
				#Unapply must NOT BE COMPLEX because it is called LOTS OF TIMES
				#It must *NOT* reset the "needapply" bit either!

        my $self = shift;
	my $applystate = shift;
        my %cmds;

        my $pol_id = $self->{_pol_id}->getID;
        my $router = $self->{_router};
        my $interface = $self->{_interface};
        my $direction = $self->{_direction};

	#Get the type of ACL and use it to set the command style
	my ($aclinterface,$aclname,$aclapplydirective,$emptyaclrules) = $self->_getacldirectives($self->{_interface},$self->{_pol_id}->getName,$self->{_pol_id}->getID,$self->{_pol_id}->getTypeS);

        $self->_debug ("UNAPPLY Application $self->{_id} AS was $applystate");

	unless ($applystate == 4) {

		if ($self->_isaclneeded) {
                	$self->_spoolcmd(\%cmds,$router,$interface);
                	$self->_spoolcmd(\%cmds,$router,"no $aclapplydirective $aclname $direction");
			$self->_spoolcmd(\%cmds,$router,"exit");
			$self->_debug ("UNAPPLY We think ACL is needed so we will leave it here ");
		}
		else {
                	$self->_spoolcmd(\%cmds,$router,$interface);
                	$self->_spoolcmd(\%cmds,$router,"no $aclapplydirective $aclname $direction");
			$self->_spoolcmd(\%cmds,$router,"exit");
			$self->_debug ("UNAPPLY We think ACL is no longer needed so we will remove it ");
			$self->_spoolcmd(\%cmds,$router,"no access-list extended $aclname");
		}
	}
	else {
		my %cmds;
                $self->_spoolcmd(\%cmds,$router,$interface);
                $self->_spoolcmd(\%cmds,$router,"no $aclapplydirective $aclname $direction");
		$self->_spoolcmd(\%cmds,$router,"exit");
		return (\%cmds);
	}
	

        $self->_debug ("UNAPPLY Application $self->{_id} AS was $applystate");
	foreach my $router (sort keys %cmds) {
		print "ROUTER: $router\n";
		print "conf t\n";
		foreach my $cmd (@{$cmds{$router}}) {
			print "$cmd\n";
		}
		print "end\n";
	}

}



sub setNeedApply {

	my $self = shift;

	my $state = shift;

	$self->{_needapply} = $state;
	#Now, do not go via commit since commit will always set needapply to 1
	my $id = $self->getID;
	$self->_debug("application $id is setting needApply state to $state");
	my $sql = "update applications set needapply='$state' where id=$id;";
	$dbi->do($sql);

	return;

}

1;
__END__

