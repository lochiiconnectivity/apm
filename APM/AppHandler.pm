#!/usr/bin/perl
#


package APM::AppHandler;

use APM::DBI;
use APM::Application;
use strict;
use Carp;
use Readonly;
use Data::Dumper;
use Scalar::Util 'blessed';



=pod

=head1 NAME

        APM::AppHandler

=head1 ABSTRACT

        Class to implement an Access Policy Manager Policy Application Handler (useful functions for applications)

=head1 SYNOPSIS

	use APM;
        use APM::AppHandler;

        #################
        # class methods #
        #################
        $apmAppHandler    = APM::AppHandler->new      (                               #Initialise class

                                                debug => [0|1|2],       #Debug can be switched on, 1 is standard, 2 is with callstack
                                        	debugfile => $filename, #Debug can be sent to a file instead of STDOUT
                                        	debugstream => [0|1]    #Debug can be mirrored to a stream as well
                                                                	#Call getDebugStream to retrieve

						dbi => APM::DBI		#APM DBI object if you dont want to open a new DB connection

                                );


	$apmAppHandler->notifyApply($object);			#Tell the handler that $object has changed
								#So it can then set needApply flag on all applications
								#Which depend on it
								#Accepts only APM::Object, APM::Policy and APM::Policy::Rule


	$apmAppHandler->checkNeedApply([$app]);		#Check if any applications need applying and apply them	
							#Optionally force re-application of $app

        #######################
        # object data methods #
        #######################


	######################
	# object properties  #
	######################


=head1 DESCRIPTION

	APM::AppHandler implements an interface to Handler functions, for instance, when updating an lower layer object,
 	the handler can marshall setting of the needApply flags in each Application object

	my $apmApp = APM::AppHandler->new();

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

sub notifyApply {			#Notify an application that a dependant policy or object has changed

	my $self = shift;

	my $object = shift;

	unless (blessed ($object)) {
		croak "You must pass NOFITYAPPLY a valid object!";
	}
	else {
		if ($object->isa('APM::Object')) {
			$self->_debug("NOTIFYAPPLY: An APM::Object was passed, digging out the app for it...");
			my $id = $object->getID;
			my $sql = "
					SELECT DISTINCT
					a.id, a.needapply
					FROM
					policy_rules r
					LEFT JOIN
					objects o ON ( 
					r.proto_obj = o.id OR
					r.s_ip_obj = o.id OR
					r.s_port_obj = o.id OR
					r.d_ip_obj = o.id OR 
					r.d_port_obj = o.id )
					LEFT JOIN
					policies p ON ( r.pol_id = p.id )
					LEFT JOIN
					applications a ON ( a.pol_id = p.id )
					WHERE o.id = '$id';
			";
			my $results = $dbi->query($sql);
			unless ($$results[0]) {
				$self->_debug("NOTIFYAPPLY: No applications depend on this APM::Object, Handler terminating");
				return;
			}
			foreach my $result (@{$results}) {
				my $appid 	= $result->{id};
				next unless ($appid);
				my $needapply 	= $result->{needapply};
				$self->_debug("NOTIFYAPPLY: Application $appid depends");
				if ($needapply == 1) { $self->_debug("NOTIFYAPPLY: Application $appid already needs apply, skipping"); }
				else {
					my $newapp = APM::Application->new();
					$newapp->load($appid) || croak "Can't load application $id in!";
					$newapp->setNeedApply(1);
					$self->_debug("NOTIFYAPPLY: Application $appid Set to 'Needs apply' due to change in ObjectID $id");
				}
			}
		}
		elsif ($object->isa('APM::Policy')) {
			$self->_debug("NOTIFYAPPLY: An APM::Policy was passed, digging out the app for it...");
			my $id = $object->getID;
			my $sql = "
					SELECT
					a.id, a.needapply
					FROM
					policies p
					LEFT JOIN
					applications a ON ( a.pol_id = p.id )
					WHERE p.id = '$id';
			";
			my $results = $dbi->query($sql);
			unless ($$results[0]) {
				$self->_debug("NOTIFYAPPLY: No applications depend on this APM::Policy, Handler terminating");
				return;
			}
			foreach my $result (@{$results}) {
				my $appid 	= $result->{id};
				next unless ($appid);
				my $needapply 	= $result->{needapply};
				$self->_debug("NOTIFYAPPLY: Application $appid depends");
				if ($needapply == 1) { $self->_debug("NOTIFYAPPLY: Application $appid already needs apply, skipping"); }
				else {
					my $newapp = APM::Application->new();
					$newapp->load($appid) || croak "Can't load application $id in!";
					$newapp->setNeedApply(1);
					$self->_debug("NOTIFYAPPLY: Application $appid Set to 'Needs apply' due to change in PolicyID $id");
				}
			}

		}
		elsif ($object->isa('APM::Policy::Rule')) {
			$self->_debug("NOTIFYAPPLY: An APM::Policy::Rule was passed, digging out the app for it...");
			my $id = $object->getID;
			my $sql = "
					SELECT
					a.id, a.needapply
					FROM
					policy_rules r
					LEFT JOIN
					policies p ON (r.pol_id = p.id)
					LEFT JOIN
					applications a ON ( a.pol_id = p.id )
					WHERE r.id = '$id';
			";
			my $results = $dbi->query($sql);
			unless ($$results[0]) {
				$self->_debug("NOTIFYAPPLY: No applications depend on this APM::Policy::Rule, Handler terminating");
				return;
			}
			foreach my $result (@{$results}) {
				my $appid 	= $result->{id};
				next unless ($appid);
				my $needapply 	= $result->{needapply};
				$self->_debug("NOTIFYAPPLY: Application $appid depends");
				if ($needapply == 1) { $self->_debug("NOTIFYAPPLY: Application $appid already needs apply, skipping"); }
				else {
					my $newapp = APM::Application->new();
					$newapp->load($appid) || croak "Can't load application $id in!";
					$newapp->setNeedApply(1);
					$self->_debug("NOTIFYAPPLY: Application $appid Set to 'Needs apply' due to change in RuleID $id");
				}
			}
				
		}
		else {
			croak "You must pass NOFITYAPPLY a valid object that it knows about!";
		}

	}

}


sub checkNeedApply {

        my $self = shift;
	
	my $appforce = shift;

	if ($appforce) {
		if ($appforce->isa('APM::Application')) {
			my $appid = $appforce->getID;
			$self->_debug ("FORCING Application $appid to be re-applied");
			$appforce->apply;
			return;
		}
		else {
			croak "FORCE MUST be a valid APM::Application!";
		}
	}

        $self->_debug ("Checking if any applications need applying...");

        my $sql = "select * from applications where needapply != '0' and enabled = 1;";

        my $results = $dbi->query($sql) || croak "Can't execute sql $!";

        unless ($$results[0]) {
                $self->_debug ("No applications need applying");
                return;
        }
        else {  
                $self->_debug ("The following applications need applying:");
		my %seenfullapplypolrouter;	#Have we seen a full apply for a policy and router?
                foreach my $result (@{$results}) {
                        $self->_debug ( "Need to apply ID : $result->{id}" );
			my $apmapp = APM::Application->new(
				debug		=>	$self->{_debug},
				debugstream	=>	$self->{_debugstream},
				debugfile	=>	$self->{_debugfile},
				dbi		=>	$dbi,
			);
			my $appidtoapply = $result->{id};
			my $appneedapply = $result->{needapply};
			my $apppolid = $result->{pol_id};
			my $approuter = $result->{router};
                        $apmapp->load($appidtoapply) || croak "Can't load application $appidtoapply";
                        $self->_debug ( "Request apply of application $appidtoapply with AS $appneedapply ....");
			if ($appneedapply == 1) {	#Full apply needed
				unless ($seenfullapplypolrouter{$approuter}{$apppolid}) {	#Did we do full apply of pol on router already?
					$self->_debug ( "Applying with FULL APPLY (1) because seenfullapplypolrouter{$approuter}{$apppolid} is not defined");
					$apmapp->apply(1);	#Ok, do a level one apply then
					$seenfullapplypolrouter{$approuter}{$apppolid}=1;	#But record we did that;
				}
				else {	#Well, if we say we already did this, then check it has actually been done, dont trust anybody
					my $sql = "select * from applications where id=$appidtoapply";
					my $results = $dbi->query($sql);
					croak "Internal Error: the following sql in checkNeedApply returned no results, this is bad, we expect there to be: $sql" unless ($$results[0]);
					my $appneedapply = $$results[0]->{needapply};
					if ($appneedapply > 0) {
						$self->_debug ( "Applying application $appidtoapply with AS $$results[0]->{needapply} because it was not performed");
						$apmapp->apply($appneedapply);
					}
					else {
						$self->_debug ( "Skipping checkNeedApply->apply for application $appidtoapply because it has been performed as expected by the previous full apply");
					}
					
				}
			}
			else {
                        	$apmapp->apply($result->{needapply});	#Do what the DB tells us to do 
			}		
                        $self->_debug ( "Applied....");
                }

		#Deal with config
		#
                return;
        }

}

1;
__END__

