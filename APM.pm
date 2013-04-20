#!/usr/bin/perl
package APM;

use strict;
use Carp;
use Readonly;
use APM::DBI;
use APM::Object;
use APM::Policy;
use APM::Policy::Rule;
use APM::Application;
use APM::AppHandler;
use APM::Importer;
use POSIX qw(strftime);
use Scalar::Util 'blessed';
use Data::Dumper;


=pod

=head1 NAME

        APM

=head1 ABSTRACT

        Class to implement the Access Policy Manager
        Version 1.00 - tdcdf1

=head1 SYNOPSIS

        use APM;

        #################
        # class methods #
        #################
	$apm	= APM->new	(				#Initialise class
                                        debug => [0|1|2],       #Debug can be switched on, 1 is standard, 2 is with callstack
					debugfile => $filename, #Debug can be sent to a file instead of STDOUT
					debugstream => [0|1]    #Debug can be mirrored to a stream as well
								#Call getDebugStream to retrieve

					allowedToDestroy => [0|1],      #Data destruction arm or not

				);



	$object = APM->newObject (		#Create a new APM::Object and commit it to the object store

                                                type            =>      APM Object type as a string or id,
                                                obj_group_type  =>      Type that group will hold if object is a group
						[scope		=>	Object scope]
                                                name            =>      Object name
                                                value           =>      Object value (network, port etc..)
                                                enabled         =>      Object enabled state (1 or 0)

				);

	$objlist        = APM->listObject(	# List all objects, optionally filter by group or scopeID
						group		=>	filter by groupid,
						scope		=>	filter by scopeid,
					);	

	$object = APM->loadObject ( $id | $name );	#Load in object by ID or Name


	APM->editObject ($object, \%editRef);	#Edit an object by passing a reference to a hash of updated values

	$policy = APM->newPolicy (		#Create a new APM::Policy and commit it to the policy store

                                                type            =>      APM Policy type as a string or id,
                                                name            =>      Policy name
                                                enabled         =>      Policy enabled state (1 or 0)

			);

	$policy = APM->loadPolicy ( $id | $name );	#Load in policy by ID or Name

	APM->editPolicy ($policy, \%editRef);	#Edit a policy by passing a reference to a hash of updated values

	$pollist	= APM->listPolicy;			#List all policies (provides a hash)

        $policy = APM->newRule (                #Create a new APM::Rule and commit it to the rule store

                                                pol_id          =>      An APM::Policy object
                                                [pol_seq]       =>      Sequence number in policy [optional: will insert at end if not present]
                                                action          =>      String, either 'permit' or 'deny'
                                                proto_obj       =>      An APM::Object representing an IP Protocol
                                                s_ip_obj        =>      An APM::Object representing a source IP Address
                                                s_port_obj      =>      An APM::Object representing a source TCP/UDP port
                                                d_ip_obj        =>      An APM::Object representing a dest IP Address
                                                d_port_obj      =>      An APM::Object representing a dest TCP/UDP port
                                                flags           =>      A string of flags (not currently supported)
                                                annotation      =>      An annotation string
                                                enabled         =>      APM Policy Rule enabled state (1 or 0)

                        );

        $rule = APM->loadRule ( $id | $name );      #Load in rule by ID or Name

        APM->editRule ($rule, \%editRef);           #Edit a rule by passing a reference to a hash of updated values

	$rullist	= APM->listRule ([polid]); 			#List all rules (provides a hash), optionally filter by
									#Policy ID


	$apmApp = APM->newApplication (		#Create a new APM::Application and commit it to the Application store

						pol_id          =>      An APM::Policy object
						router		=>	Name of RANCID router to apply policy to
						interface	=>	Name of RANCID router interface to apply policy to
						direction	=>	Direction to apply policy to [in|out]
                                                enabled         =>      Application enabled state (1 or 0)
	);

	$apmApp = APM->loadApplication ( $id );		#Load in application by ID

	APM->editApplication ($apmApp, \%editRef);      #Edit an application by passing a reference to a hash of updated values

	$applist	= APM->listApp ([$polid]); 	#List all rules (provides a hash), optionally filter by
							#Policy ID they are applied to
							OR
	@apps		= APM->getPolApp ($polid);	#Returns all applications (as application objects) referred to by a policy
							

	APM->mergePol ($srcpolid,$dstpolid,[$apply]);	#Merge policy with srcpolid into dstpolid. Will completely eradicate srcpolid
							#and replace all applications which refer to it with references to dstpolid.
							#If $apply is populated will apply the changes and destroy the old policy

	APM->checkNeedApply([appid]);			#check if any applications need applying and apply them
							#Optionally force app with APPID to be reapplied

	APM->dbStatus;					#check on the status of the database and return the status

	APM->importConfig($config,$apply);		#Import router configurations into APM, provide the entire
							#Router configuration as the first element of the list.
							#The second element is optional and if provided will 
							#commit applications when they are created




        #######################
        # object data methods #
        #######################



=head1 DESCRIPTION


=head1 TODO

	Tidy POD

=cut

my $dbi;
my $apphandler;

sub new {
        my $proto = shift;
        my $class = ref($proto) || $proto;
        my $self = {};
        bless($self, $class);

	#Process instantuation arguments
	if (@_ > 1) {
		my %args = @_;
		foreach (keys %args) {
			$self->{$_}=$args{$_};
		}
	}
        $self->_init;
        return $self;
}

#Initialise our environment
sub _init {

        my $self = shift;

	#Version
	$self->{_version} = "1.00";

	#Find out who we are for transactions
	if ($ENV{'REMOTE_USER'}) {			#Via HTTP?
		$self->{'username'} = $ENV{'REMOTE_USER'};
	}
	elsif ($ENV{'LOGNAME'}) {			#Via shell?
		$self->{'username'} = $ENV{'LOGNAME'};
	}
	else {
		$self->{'username'} = 'unknown';
	}

 	#Initialise the DBI connection
 	$dbi = APM::DBI->new( 
					debug		=>	$self->{debug},
					debugfile	=>	$self->{debugfile},
					debugstream	=>	$self->{debugstream},
				);

	#Initialise types database
	$self->{_types} 	= $dbi->{types};
 	$self->{_typesbyid} 	= $dbi->{typesbyid};

	#Initialise scopes database
	$self->{_scopes} 	= $dbi->{scopes};
 	$self->{_scopesbyid} 	= $dbi->{scopesbyid};

	#Initialise the Application Handler
	$apphandler = APM::AppHandler->new(
	                                        debug           =>      $self->{debug},
	                                        debugfile       =>      $self->{debugfile},
	                                        debugstream     =>      $self->{debugstream},
						dbi		=>	$dbi,
	) || croak "Couldn't initialise Application Handler !";

	#Show we initialised successfully
	$self->_debug("APM Initialised Successfully");
	

}

#Cleanup our environment
sub _cleanup {
        my $self = shift;
        #Close DB
        $self->{_dbh}->disconnect();

}

#Destructor

sub DESTROY {

        my $self = shift;
        $self->_cleanup;        #Cleanup the environment

}

#Debug
#WARNING - DO NOT CLONE THIS DEBUG FOR ANY OTHER OBJECTS, VARIABLES FOR SELF() HERE
#ARE **NOT** PREFIXED WITH UNDERSCORE WHEREAS THEY ARE EVERYWHERE ELSE
sub _debug {
	my $self = shift;
	my $msg = shift;
	return unless ($self->{'debug'});

        #Identify caller
        if ($self->{'debug'} == 2) {   #Callstack debug

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

	if ($self->{'debugfile'}) {
		open (DEBUGFILE, ">>$self->{'debugfile'}") || return;
		print DEBUGFILE "$msg\n";
		close (DEBUGFILE);
	}
	else {
		if ($self->{'debugstream'}) {
			$self->{'debug_stream'} .= "$msg\n";
		}
		else {
			print STDERR "$msg\n";
		}
	}
	return;
}

sub getDebugStream {	#Public interface for the debug stream

	my $self = shift;
	return $self->{'_debug_stream'};

}

sub _now {	#Get strftime and make it safe.

	my $now = strftime "%Y%m%e", localtime;
	$now=~s/\s+/0/g;
	return ($now);

}

sub _transact {		#Create a database transaction
	my $self = shift;
	my $data = shift;
	return unless ($data);
	$self->_debug("Inserting Transaction: $data");
	my $sql = "insert into transactions values ('',NOW(),\'$self->{'username'}\',\'$data\');";
	$self->_debug($sql);
	$self->_dbdo($sql);
	return 1;
}

sub getVersion {

	my $self = shift;

	return $self->{_version};

}

sub getTypesDB {
	
	my $self = shift;
	return ($self->{_types},$self->{_typesbyid});

}
sub getScopesDB {
	
	my $self = shift;
	return ($self->{_scopes},$self->{_scopesbyid});

}
sub newObject {			#Provides short helpful way to create and commit a new APM::Object
	
	my $self = shift;
	my %objdata = @_;
	
	$objdata{debug} = $self->{debug};
	$objdata{debugfile} = $self->{debugfile};
	$objdata{debugstream} = $self->{debugstream};
	$objdata{dbi} = $dbi;
	$objdata{apphandler} = $apphandler;

	my $object = APM::Object->new( %objdata ) || croak "Can't create new APM::Object $! ";

	my ($objid,$objret) = $object->commit;

	if ($objret) {		#Object must have already existed, we need to replace it
		undef ($object);
		$object = $self->loadObject($objid);
	}

	return ($object);

}

sub listObject {		#Provides a list of all objects

	my $self = shift;
	my %filtdata = @_;

	my $results;
	my $sql = 'select * from objects';

	if ($filtdata{group}) {
		$sql .= " right join obj_groups on (objects.id = obj_groups.obj_id) where obj_group_id = '$filtdata{group}'";
	}
	if ($filtdata{scope}) {
		$sql .= " where scope = '$filtdata{scope}'";
	}

	$sql .= " order by objects.type, objects.id;";

	my $results = $dbi->query($sql);

	return ($results);

}

sub loadObject {	       	#Provides short helpful way to create a blank APM::Object and load into it

	my $self = shift;

	my $in = shift;

	my $type = shift;

	my %objdata;

        $objdata{debug} = $self->{debug};
        $objdata{debugfile} = $self->{debugfile};
        $objdata{debugstream} = $self->{debugstream};
        $objdata{dbi} = $dbi;
	$objdata{apphandler} = $apphandler;
	my $object = APM::Object->new( %objdata ) || croak "Can't create new APM::Object $! ";
	$object->load($in,$type) || croak "Can't load APM::Object $in $!";

	return ($object);

}

sub editObject {	#Provide for editing an object, takes on task of creating new and duplicating values

	my $self = shift;
	my $obj = shift;
	my $inhash = shift;

	unless ((blessed ($obj)) && $obj->isa('APM::Object')) {
		croak "You MUST provide a valid APM::Object!";
	}

	$self->_debug ("Initialising new object based on inhash paramaters");

	if ((defined($inhash->{type})) || (defined($inhash->{obj_group_type}))) {
		croak "you can not modify types dynamically, you must delete and re-create the object";
	}

	#Enabled option does not actually do anything, leaving in here for future use
	my $enablevalue;
	if (defined($inhash->{enabled})) {
		$enablevalue = $inhash->{enabled};
	}
	else {
		$enablevalue = $obj->getEnabled;
	}
	

	my $newobj = APM::Object->new (

					debug		=>	$self->{debug},
					debugfile	=>	$self->{debugfile},
					debugstream	=>	$self->{debugstream},
					dbi		=>	$dbi,
					apphandler	=> 	$apphandler,
					id		=>	$obj->getID,
					type		=>	$inhash->{type} 		|| 	$obj->getType,
					obj_group_type	=>	$inhash->{obj_group_type} 	|| 	$obj->getObjGroupType,
					name		=>	$inhash->{name} 		|| 	$obj->getName,
					value		=>	$inhash->{value} 		|| 	$obj->getValue,
					enabled		=>	int($enablevalue),
		);

	$self->_debug ("Old object follows:\n\n");
	$self->_debug (Dumper($obj));
	$self->_debug ("\n\n");
	$self->_debug ("New object follows:\n\n");
	$self->_debug (Dumper($newobj));
	$self->_debug ("\n\n");

	$self->_debug ("Committing object...");

	$newobj->commit();

	return($newobj);


}

sub newPolicy {		#Provides short helpful way to create and commit new APM::Policy

        my $self = shift;
        my %poldata = @_;

        $poldata{debug} = $self->{debug};
        $poldata{debugfile} = $self->{debugfile};
        $poldata{debugstream} = $self->{debugstream};
        $poldata{dbi} = $dbi;
	$poldata{apphandler} = $apphandler;

        my $policy = APM::Policy->new( %poldata ) || croak "Can't create new APM::Policy $! ";

        $policy->commit;

        return ($policy);

}

sub loadPolicy {	#Provides short helpful way to create new APM::Policy and load into it

        my $self = shift;

        my $in = shift;

        my %poldata;

        $poldata{debug} = $self->{debug};
        $poldata{debugfile} = $self->{debugfile};
        $poldata{debugstream} = $self->{debugstream};
        $poldata{dbi} = $dbi;
	$poldata{apphandler} = $apphandler;

        my $policy = APM::Policy->new( %poldata ) || croak "Can't create new APM::Policy $! ";
        $policy->load($in) || croak "Can't load APM::Policy $in $!";

        return ($policy);

}

sub editPolicy {        #Provide for editing a policy, takes on task of creating new and duplicating values

        my $self = shift;
        my $pol = shift;
        my $inhash = shift;

        unless ((blessed ($pol)) && $pol->isa('APM::Policy')) {
                croak "You MUST provide a valid APM::Policy!";
        }

        $self->_debug ("Initialising new policy based on inhash paramaters");

        my $enablevalue;
        if (defined($inhash->{enabled})) {
                $enablevalue = $inhash->{enabled};
        }
        else {
                $enablevalue = $pol->getEnabled;
        }


        my $newpol = APM::Policy->new ( 

					debug		=>	$self->{debug},
					debugfile	=>	$self->{debugfile},
					debugstream	=>	$self->{debugstream},
					dbi		=>	$dbi,
					apphandler	=> 	$apphandler,
                                        id              =>      $pol->getID,
                                        type            =>      $inhash->{type} 		|| 	$pol->getType,
                                        name            =>      $inhash->{name} 		|| 	$pol->getName,
                                        enabled         =>      int($enablevalue),
                );

        $self->_debug ("Old policy follows:\n\n");
        $self->_debug (Dumper($pol));
        $self->_debug ("\n\n");
        $self->_debug ("New policy follows:\n\n");
        $self->_debug (Dumper($newpol));
        $self->_debug ("\n\n");

        $self->_debug ("Committing policy...");

        $newpol->commit();

        return ($newpol);


}

sub listPolicy {                #Provides a list of all policies

        my $self = shift;

        my $results;
        my $sql;

        $sql = "select * from policies order by type;";

        my $results = $dbi->query($sql);

        return ($results);

}

sub listRule {                #Provides a list of all rules

        my $self = shift;

	my $rulfilter = shift;

        my $results;
        my $sql;
	$sql = "	SELECT 
			r.id,
			r.pol_id,
			r.pol_seq,
			r.action,
			r.proto_obj,
			o1.name as proto_obj_name,
			r.s_ip_obj,
			o2.name as s_ip_obj_name,
			r.s_port_obj,
			o3.name as s_port_obj_name,
			r.d_ip_obj,o4.name as d_ip_obj_name,
			r.d_port_obj,o5.name as d_port_obj_name,
			r.annotation,
			r.enabled from policy_rules r 
			LEFT JOIN objects o1 on (r.proto_obj = o1.id) 
			LEFT JOIN objects o2 on (r.s_ip_obj = o2.id)
			LEFT JOIN objects o3 on (r.s_port_obj = o3.id) 
			LEFT JOIN objects o4 on (r.d_ip_obj = o4.id) 
			LEFT JOIN objects o5 on (r.d_port_obj = o5.id)

	";

	if ($rulfilter=~m/(\d+)/) {
		$sql .= " where pol_id = $1 ";
	}

	$sql .= "ORDER BY r.pol_id,r.pol_seq;";

        my $results = $dbi->query($sql);

        return ($results);

}



sub newRule {		#Provides short, helpful way to create a Policy Rule

        my $self = shift;
        my %ruledata = @_;

        $ruledata{debug} = $self->{debug};
        $ruledata{debugfile} = $self->{debugfile};
        $ruledata{debugstream} = $self->{debugstream};
        $ruledata{dbi} = $dbi;
	$ruledata{apphandler} = $apphandler;

	unless ($ruledata{pol_seq}) {		#If no sequence number was provided, make it the last
		if ($ruledata{pol_id}) {
			my $maxseq = $ruledata{pol_id}->_getMaxSeq;
			$maxseq++;
			$ruledata{pol_seq} = $maxseq;
			$self->_debug("No policy seq provided, APM will fill this in as $maxseq");
		}
	}

        my $rule = APM::Policy::Rule->new( %ruledata ) || croak "Can't create new APM::Policy::Rule $! ";

        $rule->commit;

        return ($rule);

}

sub loadRule {	#Provides short helpful way to create new APM::Policy::Rule and load into it

        my $self = shift;

        my $in = shift;

        my %ruledata;

        $ruledata{debug} = $self->{debug};
        $ruledata{debugfile} = $self->{debugfile};
        $ruledata{debugstream} = $self->{debugstream};
        $ruledata{dbi} = $dbi;
	$ruledata{apphandler} = $apphandler;

        my $rule = APM::Policy::Rule->new( %ruledata ) || croak "Can't create new APM::Policy::Rule $! ";
        $rule->load($in) || croak "Can't load APM::Policy::Rule $in $!";

        return ($rule);

}

sub editRule {        #Provide for editing a rule, takes on task of creating new and duplicating values

        my $self = shift;
        my $rule = shift;
        my $inhash = shift;

        unless ((blessed ($rule)) && $rule->isa('APM::Policy::Rule')) {
                croak "You MUST provide a valid APM::Policy::Rule";
        }

        $self->_debug ("Initialising new rule based on inhash paramaters");

        my $enablevalue;
        if (defined($inhash->{enabled})) {
                $enablevalue = $inhash->{enabled};
        }
        else {
                $enablevalue = $rule->getEnabled;
        }

        my $newrule = APM::Policy::Rule->new ( 

					debug		=>	$self->{debug},
					debugfile	=>	$self->{debugfile},
					debugstream	=>	$self->{debugstream},
					dbi		=>	$dbi,
					apphandler	=> 	$apphandler,
                                        id              =>      $rule->getID,
					pol_id		=>	$inhash->{pol_id}		||	$rule->getPolID,
					pol_seq		=>	$inhash->{pol_seq}		||	$rule->getPolSeq,
					action		=>	$inhash->{action}		||	$rule->getAction,
					proto_obj       =>      $inhash->{proto_obj}		||	$rule->getProtoObj,
					s_ip_obj        => 	$inhash->{s_ip_obj}		||	$rule->getSIPObj,
					s_port_obj      =>     	$inhash->{s_port_obj}		||	$rule->getSPortObj, 
					d_ip_obj        =>      $inhash->{d_ip_obj}		||	$rule->getDIPObj,
					d_port_obj      =>      $inhash->{d_port_obj}		||	$rule->getDPortObj,
					flags           =>	$inhash->{flags}		||	$rule->getFlags,
					annotation      =>	$inhash->{annotation}		||	$rule->getAnnotation,
                                        enabled         =>      int($enablevalue),
                );

        $self->_debug ("Old rule follows:\n\n");
        $self->_debug (Dumper($rule));
        $self->_debug ("\n\n");
        $self->_debug ("New rule follows:\n\n");
        $self->_debug (Dumper($newrule));
        $self->_debug ("\n\n");

        $self->_debug ("Committing rule...");

        $newrule->commit();

        return($newrule);


}

sub newApplication {		#Provides short, helpful way to create an application

        my $self = shift;
        my %applicationdata = @_;

        $applicationdata{debug} = $self->{debug};
        $applicationdata{debugfile} = $self->{debugfile};
        $applicationdata{debugstream} = $self->{debugstream};
        $applicationdata{dbi} = $dbi;

        my $application = APM::Application->new( %applicationdata ) || croak "Can't create new APM::Application $! ";

        $application->commit;

        return ($application);

}

sub loadApplication {	#Provides short helpful way to create new APM::Application and load into it

        my $self = shift;

        my $in = shift;

        my %applicationdata;

        $applicationdata{debug} = $self->{debug};
        $applicationdata{debugfile} = $self->{debugfile};
        $applicationdata{debugstream} = $self->{debugstream};
        $applicationdata{dbi} = $dbi;

        my $application = APM::Application->new( %applicationdata ) || croak "Can't create new APM::Application $! ";
        $application->load($in) || croak "Can't load APM::Application $in $!";

        return ($application);

}

sub editApplication {        #Provide for editing an application , takes on task of creating new and duplicating values

        my $self = shift;
        my $application = shift;
        my $inhash = shift;

        unless ((blessed ($application)) && $application->isa('APM::Application')) {
                croak "You MUST provide a valid APM::Application";
        }

	if ($inhash->{pol_id} || $inhash->{router} || $inhash->{interface} || $inhash->{direction}) {	#Only allow enable/disable
		croak "You can not modify these values in an installed application, please create a new one";
	}

        $self->_debug ("Initialising new application based on inhash paramaters");

        my $enablevalue;
        if (defined($inhash->{enabled})) {
                $enablevalue = $inhash->{enabled};
        }
        else {
                $enablevalue = $application->getEnabled;
        }

        my $newapplication = APM::Application->new ( 
					
					debug		=>	$self->{debug},
					debugfile	=>	$self->{debugfile},
					debugstream	=>	$self->{debugstream},
					dbi		=>	$dbi,
                                        id              =>      $application->getID,
					pol_id		=>	$application->getPolID,
					router		=>	$application->getRouter,
					interface	=>	$application->getInterface,
					direction	=>	$application->getDirection,
                                        enabled         =>      int($enablevalue),
                );

        $self->_debug ("Old application follows:\n\n");
        $self->_debug (Dumper($application));
        $self->_debug ("\n\n");
        $self->_debug ("New application follows:\n\n");
        $self->_debug (Dumper($newapplication));
        $self->_debug ("\n\n");

	#Any edited applications must be pre-committed first to see if they will commit properly

        $self->_debug ("Committing application...");

        $newapplication->commit;

        return($newapplication);

}

sub listApp {                #Provides a list of all applications

        my $self = shift;

        my $appfilter = shift;

        my $results;
        my $sql;
        $sql = "select * from applications";

        if ($appfilter=~m/(\d+)/) {
                $sql .= " where pol_id = $1 ";
        }

        my $results = $dbi->query($sql);

        return ($results);

}

sub checkNeedApply {		#Check if any applications need applying

	my $self = shift;

	my $appforce = shift;
	my $app;

	if ($appforce) {
		$app = $self->loadApplication($appforce);
	}

	$apphandler->checkNeedApply($app);

	return;

}	

sub dbStatus {			#Get status from DB

	my $self = shift;

	my $status = $dbi->status;

	return $status;

}

sub importConfig {		#Import configuration

	my $self = shift;

	my $config = shift;
	
	my $apply = shift;

	croak "No config specified!" unless ($config);


	my $importer = APM::Importer->new(
						debug		=>	$self->{debug},
						debugfile	=>	$self->{debugfile},
						debugstream	=>	$self->{debugstream},
						config		=>	$config,
						apply		=>	$apply,
	);
	return;

}

sub getPolApps {		#Get applications that a policy ID is referred to by, returns a list of applications

	my $self = shift;

	my $polid = shift;

	croak "No policy ID specified!" unless ($polid);

	my $results = $self->listApp($polid);

	my @appstoreturn;

	if ($$results[0]) {
		foreach my $result (@{$results}) {
			my $appid             =       $result->{id};			
			my $app = $self->loadApplication($appid);
			push (@appstoreturn,$app);
		}
		return (@appstoreturn);
	}
	else {
		return;
	}

}


sub mergePol {			#Merge policies

	my $self = shift;;
	
	my $srcpolid = shift;
	my $dstpolid = shift;

	croak "SRCPOL not specified" unless ($srcpolid);
	croak "DSTPOL not specified" unless ($dstpolid);

	#Load policies first to make sure they exist
	my $srcpol = $self->loadPolicy($srcpolid);
	croak "Can't load policy id $srcpol" unless ($srcpol);
	my $dstpol = $self->loadPolicy($dstpolid);
	croak "Can't load policy id $dstpol" unless ($dstpol);

	#Check they are of the same type
	croak "Can't merge policies of differing types" unless ($srcpol->getType == $dstpol->getType);

	$self->_debug("MERGE starts, merging policy $srcpolid into policy $dstpolid");

	#Get a list of apps referred to by the src policy
	my @applist = $self->getPolApps($srcpolid);
	if ($applist[0]) {	#Apps refer to this policy, rewrite them
		$self->_debug("MERGE found dependant applications, rewiring them");
		foreach my $app (sort @applist) {
			my $appid = $app->getID;
			$self->_debug("MERGE deleting app $appid");
			$app->destroy();	#Delete the old application
			my $newapp = $self->newApplication (
	
								pol_id	=>	$dstpol,
								router	=>	$app->getRouter,
								interface =>	$app->getInterface,
								direction =>	$app->getDirection,
								enabled	=>	$app->getEnabled,

			)
		}
		
	}

	#Now make all changes
	$self->checkNeedApply;

	#Now purge the policy 
	$srcpol->destroy;

}

1;
__END__;
+---------+---------------+------+-----+---------+----------------+
| Field   | Type          | Null | Key | Default | Extra          |
+---------+---------------+------+-----+---------+----------------+
| id      | int(10)       | NO   | PRI | NULL    | auto_increment | 
| type    | int(2)        | NO   |     | NULL    |                | 
| name    | varchar(32)   | NO   | MUL | NULL    |                | 
| value   | varchar(32)   | NO   |     | NULL    |                | 
| enabled | enum('1','0') | NO   |     | 1       |                | 
+---------+---------------+------+-----+---------+----------------+

