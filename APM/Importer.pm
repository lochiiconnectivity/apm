#!/usr/bin/perl
#


package APM::Importer;

use APM::DBI;
use APM::Importer::IOS;
use APM::AppHandler;
use strict;
use Carp;
use Readonly;
use Data::Dumper;
use Scalar::Util 'blessed';
use Smart::Comments;



=pod

=head1 NAME

        APM::Importer

=head1 ABSTRACT

        Class to implement an Access Policy Manager Policy Importer

=head1 SYNOPSIS

	use APM;
        use APM::Importer;

        #################
        # class methods #
        #################
        $apmAppHandler    = APM::Importer->new      (                               #Initialise class

                                                debug => [0|1|2],       #Debug can be switched on, 1 is standard, 2 is with callstack
                                        	debugfile => $filename, #Debug can be sent to a file instead of STDOUT
                                        	debugstream => [0|1]    #Debug can be mirrored to a stream as well
                                                                	#Call getDebugStream to retrieve

						dbi => APM::DBI		#APM DBI object if you dont want to open a new DB connection

						config => $config	#Configuration data

						apply  => [0|1]		#Will apply changes once imported

                                );


        #######################
        # object data methods #
        #######################
        #

	######################
	# object properties  #
	######################


=head1 DESCRIPTION


We advise you to perform imports using the APM interface (importConfig)


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

 if ($this->{in_apply}) {
        Readonly $this->{_apply} => $this->{in_apply};
 }

 if ($this->{in_config}) {
        Readonly $this->{_config} => $this->{in_config};
	$this->_parseConfig;
 }
 else {
	croak "Configuration not supplied\n";
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

#Parse configuration
#
sub _parseConfig {

	my $self = shift;

	croak "Internal error: no config specified!" unless (my $config = $self->{_config});

	$self->_debug("configuration parsing starting");

	if ($config=~m/version 12\./) {	#Config is IOS
		my $iosparser = APM::Importer::IOS->new(
                                                	debug           =>      $self->{_debug},
                                                	debugfile       =>      $self->{_debugfile},
                                                	debugstream     =>      $self->{_debugstream},
                                                	dbi             =>      $dbi,
							);
		$iosparser->parseConfig($config);

		if ($self->{_apply}) {
			my $apphandler = APM::AppHandler->new();
			$apphandler->checkNeedApply;

		}
	}
	else {
		croak "Unrecognised configuration format!!";
	}
	

}

1;
