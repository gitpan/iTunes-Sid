package iTunes::Sid::Atom;

use strict;
use warnings;
use Carp qw( carp croak );

# A sid atom has a 4 byte length, 4 byte type, 12 byte version, then contained
# atoms.  This means it has a structure very akin to that of iTunes::M4P::Atom
# mp4 atoms, so we re-use that code.

use base 'Audio::M4P::Atom';

our $VERSION = '0.042';

our $DEBUG = 0;

#------------- useful constants and hashes --------------------#

my %sid_root_atom_types = (
    sean => 1,
    dbag => 1,
);

my %sid_container_atom_types = (
    sean => 1,    # root atom for sidb files
    dbag => 1,    # root atom for sidd files
    grup => 1,    # for all the data in the package
    head => 1,    # header atom, first thing in the sid, contains the guid
    user => 1,    # user container, contains a given user's keys
    usag => 1,    # iTunes security certificate container for valu and sign
    tail => 1,    # the last container in the sid, contains itgr

    # the "key " (4 bytes, last is a space) container atom data structure
    # is generally of fixed size, and contains valu, type, and sign atoms.
    # The type is generally 0x000100000000, and the valu and sign vary.
    # There is no key count kept in the database, just a list of key atoms.
    "key " => 1,
);

my %sid_noncontainer_atom_types = (
    vers => 1,    # version data: 12 bytes 0x000100000000 then 4 bytes 0x01010
    guid => 1,    # iTMS guid, data: 12 bytes 0x000100000000 then a 6-byte value
    valu => 1,    # 36 bytes, data: 12 bytes of 0x00010000 then variable data
    type => 1,    # 24 bytes, usually data is a redundant 0x000100000000
    sign => 1,    # signature, 148 bytes, 0x00010000000 then a 128-byte value
    itgr => 1,    # the last atom in the sid, unclear use; padding to 2**5*n?
);

#----------------- class methods ------------------------------#

sub new {
    my ( $class, %args ) = @_;
    my $self                   = $class->SUPER::new(%args);
    $self->{data_after_header} = substr $self->data(), 12;
    return $self;
}

# this overloads parent method
sub isContainer {
    if ( $sid_container_atom_types{ shift->{type} } ) {
        return 1;
    }
    else {
        return;
    }
}

sub Ending {
    my($self) = @_;
    return $self->start + $self->size;
}

# Test if a string label or an atom is a root atom type
sub isRootAtomType {
    my $type = shift;
    return $sid_root_atom_types{ ref $type ? $type->{type} : $type };
}

# get the atom's version, as 3, 32-bit big endian integers separated by '.'
sub VersionString {
    my($self) = @_;
    return join '.', unpack "NNN", $self->data;
}

sub MainVersion {
    my($self) = @_;
    return unpack "N", $self->data;
}

sub NonVersionData {
    my($self) = @_;
    return substr $self->data, 12;
}

# a common data is a 32 bit bigendian int after the 12 byte version string for a data atom
sub Data32 {
    my($self) = @_;
    return unpack "N", $self->NonVersionData;
}

1;

__END__

=head1 NAME

=over 4

iTunes::Sid::Atom - Apple iTunes database component interface

=back

=head1 SYNOPSIS

=over 4

    See iTunes::Sid documentation.
    
=back

=head1 DESCRIPTION

=over 4

    This module represents a chunk of data in Apple iTunes sid* format database files.

=back

=head1 METHODS

=over 4

=item B<new>

    my $atm = iTunes::Sid::Atom( rbuf => \$buf, read_buffer_position => $position );
    
    Create an atom object.  rbuf => \$buf is a named argument which is a 
    reference to the memory buffer containing the atom.
    read_buffer_position => $position is the offset in the buffer where the 
    atom's start for reading is located.

=item B<isContainer>

    $atom->isContainer;

    Overloaded for parent, to allow reading of atom types for container versus
    non-container atoms during parsing.

=item B<isRootAtomType>

    $atom->isRootAtomType();

    returns 1 if the atom is a root type, otherwise undef.


=item B<Ending>

    Returns the buffer location of the ending of the atom (the first byte position after the data's end)

=item B<VersionString>

    Returns the version as string of 3 ints, as in version 3.4.5 or 0.0.1


=item B<MainVersion>

    Returns the first version field integer, so version 3.4.5 returns just 3

=item B<NonVersionData>

    Returnsdata after the 12 byte version fields


=item B<Data32>

    Returns a 32 bit bigendian int after the 12 byte version string for a data atom

=back

=head1 SEE ALSO

=over 4

=item B<iTunes::Sid>

=back

=head1 AUTHOR 

=over 4

William Herrera ( B<wherrera@skylightview.com> ). 

=back

=head1 SUPPORT 

=over 4

Questions, feature requests and bug reports should go to <wherrera@skylightview.com>.

=back

=head1 COPYRIGHT 

=over 4

  Copyright (c) 2008 William Herrera. All rights reserved.  
  
  This program is restricted use but free software; you can redistribute it 
  and/or modify it under the same terms as Perl itself, BUT with the same 
  additional restrictions seen in the COPYRIGHT section of B<iTunes::Sid>.

=back

=cut

