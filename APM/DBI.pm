#!/usr/bin/perl

package APM::DBI;

use strict;
use Carp;
use Readonly;
use DBI;
use Data::Dumper;

=pod

=head1 NAME

        APM::DBI

=head1 ABSTRACT

        Class to implement an Access Policy Manager Database Access

=head1 SYNOPSIS

	use APM;
        use APM::DBI;

        #################
        # class methods #
        #################
	$apmdbi	      = APM::DBI->new;

	$apmdbi->query($sql)		Query the database with SQL, provide a reference to an array of hashes containing results
	$apmdbi->do($sql)		Execute some SQL, don't return any results
	$apmdbi->status();		Provide some database status , return a hashref


        #######################
        # object data methods #
        #######################

	my %types	= APM::DBI->types();	#Get typelibrary
	my %scopes	= APM::DBI->scopes();	#Get scopelibrary



=head1 DESCRIPTION


=head1 TODO

        Tidy POD

=cut

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


#Initialise our environment
sub _init {

        my $self = shift;

	#Control debugging
	$self->{_debug} = $self->{debug};
	$self->{_debugfile} = $self->{debugfile};
	$self->{_debugstream} = $self->{debugstream};


        #Open DB
	my $dbname = "apm";
        my $dbuser = "apm";
        my $dbpass = "apm";
        my $dbhostname = "127.0.0.1";
        my $dbconnstring = "DBI:mysql:database=$dbname;hostname=$dbhostname";
        $self->{_dbh} = DBI->connect($dbconnstring,$dbuser,$dbpass,{PrintError=>0}) || die "Can't connect to APM ($DBI::errstr)\n";

	#Load typecache
	$self->_types;
	#Load scopecache
	$self->_scopes;

}

sub do {                             #Execute an insert/update

        my $self = shift;
        my $sql = shift;

	$self->_debug("SQL $sql");

        return unless ($sql);
        if ($self->{_dbh}->do($sql)) {
        }
        else {
		#Provide some user friendly feedback
		my $errstr = $DBI::errstr;
		my $feedback = "Can not execute query: $DBI::errstr";	#Default feedback

		if ($errstr = ~ m/Duplicate entry/) {			#User is trying to make a duplicate object
			$feedback = "You can not create an object with the same name as another object of the same type.";
		}
		$self->_debug("DBI Error occured in DO, ErrStr was $DBI::errstr");
                croak ($feedback);
                return;
        }

        return 1;

}

sub begin {			     #Begin a query which may need committal, this is just a trick, all we really do is
				     #Unset autocommit for the rest of the session

		my $self = shift;
		$self->_debug("Transaction begin requested");
		$self->{_dbh}->{AutoCommit} = 0;

		return 1;

}

sub commit {			     #Commits

		my $self = shift;
		$self->{_dbh}->commit;
		$self->{_dbh}->{AutoCommit} = 1;

		return 1;

}

sub rollback {			     #Rolls back

		my $self = shift;
		$self->{_dbh}->rollback;
		$self->{_dbh}->{AutoCommit} = 1;

		return 1;

}

sub query {                          #Run a query, return an reference to an array full of references to hashes

        my $self = shift;
        my $sql = shift;
        return unless($sql);

	$self->_debug("SQL $sql");

        if (my $arrayref = $self->{_dbh}->selectall_arrayref( $sql , { Slice => {} } ) ) {
                return $arrayref;
        }
        else {
                warn "Can not execute and return query: $DBI::errstr";
                return;
        }

}

sub update {                         #Updates database rows from table called param "table" based on a known where clause, passed by a param called "where"

        my $self = shift;
        my %inhash = @_;
        return unless (%inhash);

        my $table = $inhash{'table'};
        return unless ($table);
        delete $inhash{'table'};

        my $where = $inhash{'where'};
        return unless ($where);
        delete $inhash{'where'};

        my $sql = "update $table set";

	$self->_debug("SQL $sql");

        foreach my $column (sort keys (%inhash)) {
                $sql .= " $column = '$inhash{$column}',";
        }

        chop($sql);

        $sql .= " where $where;";

        $self->do($sql);

        return;

}


sub last  {                          #Retrieve idents for insert , DBI last_insert_id is broken somehow, lets do it ourselves
        my $self = shift;
        my ($table,$field) = @_;
        return unless ($table,$field);
        my $sql = "select last_insert_id($field) as id from $table order by $field desc limit 1;";
        my $results = $self->query($sql);
        my $id = $$results[0]->{'id'};
        return $id;
}


sub _types {			      #Cache Library of APM::Object types

	my $self = shift;
	my %types;
	my %typesbyid;
	my $tresults = $self->query("select * from obj_types");
	croak "Unable to read in types database" unless $$tresults[0];
	foreach my $type (@{$tresults}) {
		$types{$type->{type}} = $type->{id};
		$typesbyid{$type->{id}} = $type->{type};
	}
	$self->{types} = \%types;
	$self->{typesbyid} = \%typesbyid;

	return;
}

sub _scopes {			      #Cache Library of APM::Object scopes

	my $self = shift;
	my %scopes;
	my %scopesbyid;
	my $tresults = $self->query("select * from obj_scopes");
	croak "Unable to read in scopes database" unless $$tresults[0];
	foreach my $scope (@{$tresults}) {
		$scopes{$scope->{scope}} = $scope->{id};
		$scopesbyid{$scope->{id}} = $scope->{scope};
	}
	$self->{scopes} = \%scopes;
	$self->{scopesbyid} = \%scopesbyid;

	return;
}

sub status {				#Retrieve Status information about the database;

	my $self = shift;

	my $objcountsql = "select count(*) as count from objects;";
	my $rulecountsql = "select count(*) as count from policy_rules;";
	my $policycountsql = "select count(*) as count from policies;";
	my $applicationcountsql = "select count(*) as count from applications";

	my %resulthash;

	eval {	$resulthash{objects} 		= ${$self->query($objcountsql)}[0]->{count};		};
	eval {	$resulthash{rules}   		= ${$self->query($rulecountsql)}[0]->{count};		};
	eval {	$resulthash{policies}		= ${$self->query($policycountsql)}[0]->{count};		};
	eval {	$resulthash{applications}	= ${$self->query($applicationcountsql)}[0]->{count};	};

	return \%resulthash;

}
1;

__END__
