#!/usr/bin/perl

package APM::Object;

use APM::DBI;
use APM::AppHandler;
use strict;
use Carp;
use Readonly;
use Data::Dumper;
use Net::Netmask;
use Net::IPv4Addr qw( :all );
use Net::IPv6Addr;
use Math::Base85;       #Required for Net::IPv6Addr RFC1924 Parsing compatibility
use Scalar::Util 'blessed';



=pod

=head1 NAME

        APM::Object

=head1 ABSTRACT

        Class to implement an Access Policy Manager Object

=head1 SYNOPSIS

	use APM;
        use APM::Object;

        #################
        # class methods #
        #################
        $apmObject    = APM::Object->new      (                               #Initialise class

                                        	debug => [0|1|2],       #Debug can be switched on, 1 is standard, 2 is with callstack
                                        	debugfile => $filename, #Debug can be sent to a file instead of STDOUT
                                        	debugstream => [0|1]    #Debug can be mirrored to a stream as well
                                                                	#Call getDebugStream to retrieve

						dbi => APM::DBI		#APM DBI object if you dont want to open a new DB connection

                                                apphandler => APM::AppHandler   #APM Application Handler object if you do not wish to
                                                                                #Open a new one

						[id]		=>	[optional: overwrite an existing object by ID]
						type		=>	APM Object type as a string or id (from %types),
						obj_group_type	=>	Type that group will hold if object is a group
						scope		=>	Object scope
						name		=>	Object name
						value		=>	Object value (network, port etc..)
						enabled		=>	Object enabled state (1 or 0)


                                );

	$apmObject->load 			($id|$name)		#Returns a populated APM::Object

	$apmObject->commit();			#Commits the object change to the database, populates the object ID, returns this ID
						#If the object data already exists in the database returns the id of the object that exists

	$apmObject->destroy();			#Deletes the object from the object store

	$apmObject->addMember			($obj)		#Add Object to OBJ_GROUP object membership
	$apmObject->delMember			($obj)		#Del Object from OBJ_GROUP object membership


        #######################
        # object data methods #
        #######################


	$apmObject->getID();			#Retrieve the ID of a committed object
	$apmObject->getType();			#Retrieve the Type of an object
	$apmObject->getTypeS();			#Retrieve the Type of an object as a string
	$apmObject->getObjGroupType();		#Retrieve the Object Group Type of an object
	$apmObject->getObjGroupTypeS();		#Retrieve the Object Group Type of an object as a string
	$apmObject->getScope();			#Retrieve the Scope of an object
	$apmObject->getName();			#Retrieve the Name of an object
	$apmObject->getValue();			#Retrieve the Value of an object
	$apmObject->getValueA;			#Retrieve the Value of an object formatted correctly for an ACL
	$apmObject->getMembers();		#Return list of APM::Object members


	######################
	# object properties  #
	######################

	These properties are READ ONLY

	_id	= Object ID
	_type	= Object Type as an id
	_s_type	= Object Type as an string
	_obj_group_type	= Object Group Type
	_s_obj_group_type = Object Group Type as a string
	_scope	= Object Scope
	_name	= Object Name
	_value	= Object Value
	_enabled = Object enabled state
	


=head1 DESCRIPTION

	APM::Object implements an interface to the APM Object, here is an example:

	my $apmObject = APM::Object->new(
						Name=> 'foo', 
						Type => 'IPV6_ADDR', 
						Value => '2001:a88::/32',
				);
	my $id = $apmObject->commit();

	my $newApmObject = $apmObject->load($id);

	use Data::Dumper;

	print Dumper($apmObject); print "\n";
	print Dumper($newApmObject); print "\n";
	
	We advise you to create objects using the APM interface (newObject)


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
	_obj_group_type		=> undef,
	_s_type			=> undef,
	_s_obj_group_type	=> undef,
	_scope			=> undef,
	_name			=> undef,
	_value			=> undef,
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
 if ($this->{in_obj_group_type}) {
	unless ($this->{_type} == $types->{OBJ_GROUP}) {
		croak "Not allowed to set group_type for non group object";
	}
	my ($t_type,$s_type) =  $this->_validatetype($this->{in_obj_group_type});
	Readonly $this->{_obj_group_type} => $t_type;
	Readonly $this->{_s_obj_group_type} => $s_type;
 }
 if ($this->{in_scope}) {
	Readonly $this->{_scope} => $this->{in_scope};
 }
 if ($this->{in_name}) {
	Readonly $this->{_name} => $this->{in_name};
 }
 if ($this->{in_value}) {
	Readonly $this->{_value} => $this->_validatevalue($this->{in_value});
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

 if ($this->{_type} == $types->{OBJ_GROUP}) {          
	unless ($this->{_obj_group_type}) {
		croak "Can not create group object without group object type";
	};
 };

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


sub _validatetype {

	my $self = shift;
	my $type = shift;
	my $typeid;

	$self->_debug("Validating type $type");

	croak "No type to validate" unless ($type);

	return $types->{OBJ_GROUP} if ($type == $types->{OBJ_GROUP});

	if ($type =~m/^(\d+)$/) {
		unless ($typesbyid->{$1}) {
			croak "Unknown object type $type";
		}
		$self->_debug("Validated: returning type numeric type $1, string type $typesbyid->{$1}");
		return ($1,$typesbyid->{$1});
	}
	elsif ($type =~m/(\w+)/) {
		unless ($types->{$1}) {
			croak "Unknown object type $type";
		}
		$self->_debug("Validated: returning type numeric type $types->{$1}, string type $1");
		return ($types->{$1},$1);
	}
	else {
		croak "Unknown object type $type";
	}
		
}

sub _validatevalue {

        my $self = shift;
        my $value = shift;

	croak "No value to validate" unless ($value);

	#Validate group values, groups must have value of OBJ_GROUP

	if ($self->{_type} == $types->{OBJ_GROUP}) {
		unless ($value eq $types->{OBJ_GROUP}) {
			croak "OBJ_GROUP objects must have value of OBJ_GROUP";
		}
	}
	elsif ($self->{_type} == $types->{IPV4_ADDR}) {

		#Test for a valid IPv4 address is to use parse_ipv4 from Net::IPv4Addr
	
		my $isipv4 = eval { ipv4_parse($value); };

		unless ($isipv4) {
			croak "Type specified as IPV4_ADDR but IPV4_ADDR (x.x.x.x/y) not provided";
		}

		if ($value=~m/\d+.\d+.\d+.\d+\/\d+.\d+.\d+.\d+/) {	#Dotted decimal muse be CIDRised
			my $nnm = Net::Netmask->new($value);
			my $cidr = $nnm->base . "\/" . $nnm->bits;
			$value = $cidr;
		}
		
		$value=~s/\/32//g;	#Remove /32

	}
	elsif ($self->{_type} == $types->{IPV6_ADDR}) {

		#Test for a valid IPv6 address is to make a valid Net::IPV6Addr out of it
		my $isipv6 = eval { Net::IPv6Addr::ipv6_parse($value) };

		unless ($isipv6) {
			croak "Type specified as IPV6_ADDR but IPV6_ADDR (x/y) not provided";
		}
		$value=~s/\/128//g;	#Remove /128

	}
	elsif ($self->{_type} == $types->{IP_PROTO}) {

		#Test for a valid IPv4 protocol
		unless (($value > 0) && ($value < 255)) {
			croak "Type specified as IP_PROTO but contains illegal value ($value)";
		}

	}
	elsif ($self->{_type} == $types->{TCP_PORT}) {

		#Test for a valid TCP port, number or range
		if (($value=~m/^(\d+)$/)) {
			croak "Type specified as TCP_PORT but contains illegal value ($value)" unless (($1 > 1) && ($1 < 65535));
		}
		elsif (($value=~m/^(lt|gt|neq) (\d+)$/i)) {
			croak "Type specified as TCP_PORT but contains illegal value ($value)" unless (($2 > 1) && ($2 < 65535));
		}
		elsif (($value=~m/^range (\d+) (\d+)$/)) {
			croak "Type specified as TCP_PORT but contains illegal value ($value)" unless (($1 > 1) && ($1 < 65535) && ($2 > 1) && ($2 < 65535));
		}
		else {
			croak "Type specified as TCP_PORT but contains illegal value ($value)";
		}

	}
	elsif ($self->{_type} == $types->{UDP_PORT}) {

                if (($value=~m/^(\d+)$/)) {
                        croak "Type specified as UDP_PORT but contains illegal value ($value)" unless (($1 > 1) && ($1 < 65535));
                }
		elsif (($value=~m/^(eq|lt|gt|le|ge) (\d+)$/i)) {
			croak "Type specified as UDP_PORT but contains illegal value ($value)" unless (($2 > 1) && ($2 < 65535));
		}
                elsif (($value=~m/^(\d+)-(\d+)$/)) {
                        croak "Type specified as UDP_PORT but contains illegal value ($value)" unless (($1 > 1) && ($1 < 65535) && ($2 > 1) && ($2 < 65535));  
                }
                else {  
                        croak "Type specified as UDP_PORT but contains illegal value ($value)";
                }

	}
	elsif ($self->{_type} == $types->{ICMP_TYPECODE}) {

		my ($icmptype,$icmpcode) = split (/ /,$value);

		if (($icmptype =~m/\D/) || ($icmpcode =~m/\D/) ) {
			croak "Type specified as ICMP_TYPECODE but ICMP_TYPE or ICMP_CODE contains illegal characters";
		}

		#Test for valid ICMP type
		unless ((($icmptype >= 0) && ($icmptype < 255)) || ($icmptype = 999999999)) {
			croak "Type specified as ICMP_TYPECODE but ICMP_TYPE contains illegal value ($icmptype)";
		}
		#Test for valid ICMP code 
		unless ( ($icmpcode >= 0) && ($icmpcode < 255) || !($icmpcode)) {
			croak "Type specified as ICMP_TYPECODE but ICMP_CODE contains illegal value ($icmpcode)";
		}

	}




	return ($value);

}

sub getID {			#Retrieve ID
	my $self = shift;
	return ($self->{_id});
}

sub getScope {			#Retrieve Scope
	my $self = shift;
	return ($self->{_scope});
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

sub getValue {			#Retrieve Value
        my $self = shift;
        return ($self->{_value});
}

sub getValueA {			#Retrieve Value formatted correctly for an ACL
	my $self = shift;
	my $type = $self->{_type};
	my $value = ($self->{_value});
	if ($type == $types->{IP_PROTO}) {
		if ($value == 1) {
			$value = "icmp";
		}
		if ($value == 6) {
			$value = "tcp";
		}
		if ($value == 17) {
			$value = "udp";
		}
	}
	if ($type == $types->{IPV4_ADDR}) {
		my $nnm = Net::Netmask->new($value);
		if ( $nnm->hostmask eq '0.0.0.0' ) {
			$value = "host " . $nnm->base;
		}
		else {
			$value = $nnm->base;
			$value .= " ";
			$value .= $nnm->hostmask;
		}
		
	}
	elsif ($type == $types->{IPV6_ADDR}) {
		unless ($value=~m/\//) {
			$value = "host $value";
		}
	}
	elsif ($type == $types->{TCP_PORT}) {
		unless ($value=~m/[a-zA-Z]/) {
			$value = "eq $value";
		}
	}
	elsif ($type == $types->{UDP_PORT}) {
		unless ($value=~m/[a-zA-Z]/) {
			$value = "eq $value";
		}
	}
	return ($value);
}

sub getEnabled {                #Retrieve Enabled
        my $self = shift;
        return ($self->{_enabled});
}

sub getObjGroupType {		#Retrieve objgrouptype
	my $self = shift;
	return ($self->{_obj_group_type});
}

sub getObjGroupTypeS {		#Retrieve objgrouptype as a string
	my $self = shift;
	return ($self->{_s_obj_group_type});
}


sub load   {			#Load from database

	my $self = shift;

	my $in = shift;
	my $type = shift;

	my $sql;

	#Liberal object loading, if simply given a number, we assume that we are being passed an ID,
	#if given anything in square brackets, we are assuming it is to be looked up as a name
	if ($in=~m/\[(.*)\]/) {
		$in = $1;
		$self->_debug("loading object with name $in");
		if ($type) {
			$self->_debug("extra constraint type of $type");
			$sql = "select * from objects where name='$in' and type='$type';";
		}
		else {
			$sql = "select * from objects where name='$in';";
		}
	}
	elsif ($in=~m/^\d+$/) {
		$self->_debug("loading object with ID $in");
		$sql = "select * from objects where id='$in';";
	}
	else {
		croak "Object type '$in' unknown";
	}



	my $results = $dbi->query($sql);

	unless ($$results[0]) {
		croak "Object $in not found in object store";
	}
	else {
		Readonly $self->{_id} 			=> $$results[0]->{id};
		Readonly $self->{_type} 		=> $$results[0]->{type};
		Readonly $self->{_s_type} 		=> $typesbyid->{$$results[0]->{type}};
		Readonly $self->{_obj_group_type} 	=> $$results[0]->{obj_group_type};
		Readonly $self->{_s_obj_group_type} 	=> $typesbyid->{$$results[0]->{obj_group_type}};
		Readonly $self->{_scope} 		=> $$results[0]->{scope};
		Readonly $self->{_name} 		=> $$results[0]->{name};
		Readonly $self->{_value} 		=> $$results[0]->{value};
		Readonly $self->{_enabled} 		=> $$results[0]->{enabled};
	}

	return 1;


}

sub commit {			#Commit to database, return ID on success

	my $self = shift;

	#Replace object method, first try to look up the object in the database,
	#if it exists, just return the object ID
	#This does NOT apply to groups
	unless ($self->{_obj_group_type}) {
		my $lookupsql = "select id from objects where type='$self->{_type}' and scope='$self->{_scope}' and value='$self->{_value}' limit 1;";
		my $lur = $dbi->query($lookupsql);
		return ($$lur[0]->{id},1) if ($$lur[0]->{id});
	}

	$self->_debug("Committing object to DB...");

	#Dont allow bad commits
	croak "Object must have a type " unless $self->{_type};
	croak "Object must be named " unless $self->{_name};
	croak "Object must have a value " unless $self->{_value};

	$self->{_scope} = 1 unless (defined($self->{_scope}));	
	$self->{_enabled} = 1 unless (defined($self->{_enabled}));

	my $sql;
	my $id;

	if ($self->{_id}) {
		$sql = "update objects set 
						type		=	'$self->{_type}',";
		$sql .="                        obj_group_type  =       '$self->{_obj_group_type}'," if ($self->{_obj_group_type});
		$sql .="			scope           =       '$self->{_scope}'",
		$sql .="			name            =       '$self->{_name}',
						value		=	'$self->{_value}',
						enabled		=	'$self->{_enabled}'
					 where id = '$self->{_id}';
		";

		my $id = $self->{_id};

		$dbi->do($sql) || croak ("couldn't commit object $!");

		$self->_debug("Object commit success, ID was $id...");

	}
	else {
		$sql = "insert into objects (id, type, obj_group_type, scope, name, value, enabled) values ('$self->{_id}','$self->{_type}'";
	
		if ($self->{_obj_group_type}) {
			$sql .= ",'$self->{_obj_group_type}',";
		}
		else {
			$sql .= ",NULL,";
		}
	
		$sql .= "'$self->{_scope}','$self->{_name}','$self->{_value}','$self->{_enabled}');";
	
		$dbi->do($sql) || croak ("couldn't commit object $!");
	
		my $id = $dbi->last('objects','id');
	
		$self->_debug("Object commit success, ID was $id...");
	
		$self->{_id} = $id;

	}

	#Notify the Application Handler that it may need to re-apply some applications
	$apphandler->notifyApply($self);

	return ($self->{_id},1);

}

sub destroy {			#Remove yourself from database providing you are not listed anywhere

        my $self = shift;

        $self->_debug("Destroying object in DB...");

	croak "Object does not have ID specified" unless $self->{_id};

	#Do not delete if we are in a group
	my $gsql = "select * from obj_groups where obj_id = '$self->{_id}';";
	my $gresult = $dbi->query($gsql);
	if ($$gresult[0]) {
		croak "Can not delete object, it is a member of a group";
	}

	my $sql = "delete from objects where id='$self->{_id}';";

	my $result = eval { $dbi->do($sql); };

	unless ($result) {

		croak "Object could not be deleted, has references";

	}

	#Application handler does not need to be notified since deletion would fail due to DB 
	#constraints if object is referenced anywhere

	return;

}


sub addMember {		#Adds a member to the group

	my $self = shift;

	croak "Can not work with uninitialised object!" unless ($self->{_id});
	croak "Can not work with non OBJ_GROUP object!" unless ($self->{_type} eq $types->{OBJ_GROUP});

	my $obj = shift;

	croak "Can not work with uninitialised member object!" unless ($obj->{_id});
	croak "Can not add OBJ_GROUP object to group!" if ($obj->{_type} == $types->{OBJ_GROUP});
	croak "Can not add object to group with mismatched type!" unless ($self->{_obj_group_type} == $obj->{_type});

	my $sql = "select * from obj_groups where obj_group_id = '$self->{_id}' and obj_id = '$obj->{_id}';";
	my $results = $dbi->query($sql);

	croak "Can not add object to group , it is already in this group!" if ($$results[0]);

	$self->_debug("Inserting object with id $obj->{_id} into group with id $self->{_id}");

	$sql = "insert into obj_groups (obj_group_id, obj_id) values ('$self->{_id}','$obj->{_id}');";

	my $result = eval { $dbi->do($sql) };

	unless ($result) {
		croak "We could not add the object membership for some reason";
	}

	#Notify the Application Handler that it may need to re-apply some applications
	$apphandler->notifyApply($self);

	return;

}

sub delMember {		#Deletes a member from a group

	my $self = shift;
	
	croak "Can not work with uninitialised object!" unless ($self->{_id});
        croak "Can not work with non OBJ_GROUP object!" unless ($self->{_type} eq $types->{OBJ_GROUP});

        my $obj = shift;

        croak "Can not work with uninitialised member object!" unless ($obj->{_id});

        my $sql = "select * from obj_groups where obj_group_id = '$self->{_id}' and obj_id = '$obj->{_id}';";
        my $results = $dbi->query($sql);

        croak "Can not remove object from group , it is not in this group!" unless ($$results[0]);

	$self->_debug("Deleting object with id $obj->{_id} from group with id $self->{_id}");

	$sql = "delete from obj_groups where obj_group_id = '$self->{_id}' and obj_id = '$obj->{_id}';";

	my $result = eval { $dbi->do($sql) };

        unless ($result) {
                croak "We could not add the object membership for some reason";
        }

	#Notify the Application Handler that it may need to re-apply some applications
	$apphandler->notifyApply($self);

        return;

}

sub getMembers {	#Return list of member objects

	my $self = shift;

        croak "Can not work with uninitialised object!" unless ($self->{_id});
        croak "Can not work with non OBJ_GROUP object!" unless ($self->{_type} eq $types->{OBJ_GROUP});

	my $sql = "select * from obj_groups where obj_group_id = '$self->{_id}';";

        my $results = $dbi->query($sql);

	return unless $results;		#Just return nothing if we dont get any members

	my @returnobjlist;

	foreach my $row (@{$results}) {
		my $newapmobject = $self->new || croak "Can't initialise a new object for my results!";
		$newapmobject->load($row->{obj_id}) || croak "Can't load in object group member!";
		$self->_debug("Pushing object with id $row->{obj_id} onto return stack for group");
		push (@returnobjlist,$newapmobject);
	}

	return (@returnobjlist);

}
		

1;
__END__

+--------------+---------+------+-----+---------+-------+
| Field        | Type    | Null | Key | Default | Extra |
+--------------+---------+------+-----+---------+-------+
| obj_group_id | int(10) | NO   | MUL | NULL    |       | 
| obj_id       | int(10) | NO   | MUL | NULL    |       | 
+--------------+---------+------+-----+---------+-------+

