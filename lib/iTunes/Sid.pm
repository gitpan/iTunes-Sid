package iTunes::Sid;

use strict;
use warnings;
use Carp qw( carp croak );
use Scalar::Util qw( weaken );

use iTunes::Sid::Atom;

our $VERSION = '0.01_01';
our $DEBUG   = 0;

#------------- useful constants and hashes --------------------#

my $sid_version_string_size = 12;

my %sid_types = (
    sean => 'sidb',
    dbag => 'sidd',
);

#----------------- class methods ------------------------------#

sub new {
    my ( $class, %args ) = @_;
    my $self = {};
    bless( $self, $class );
    foreach my $k (qw( DEBUG DEBUGDUMPFILE file)) {
        $self->{$k} = $args{$k} if exists $args{$k};
    }
    $self->{meta} = {};
    $self->{DEBUG} = 0 unless exists $self->{DEBUG};
    if ( exists $self->{file} ) {
        $self->ReadFile( $self->{file} );
        $self->ParseBuffer();
    }
    return $self;
}

sub DESTROY {
    my ($self) = @_;
    if ( ref $self->{root} ) {
        $self->{root}->DESTROY;
    }
}

sub ReadFile {
    my ( $self, $infile ) = @_;
    open( my $infh, '<', $infile ) or croak("Cannot open input $infile: $!");
    binmode $infh;
    read( $infh, $self->{buffer}, -s $infile ) or croak("Bad file read: $!");
    close $infh;
    $self->{meta}->{filesize} = length $self->{buffer};
}

sub ParseBuffer {
    my ($self) = @_;
    $self->{atom_count} = 0;
    $self->{root}       = iTunes::Sid::Atom->new(
        read_buffer_position => 0,
        rbuf                 => \$self->{buffer},
        type                 => 'file',
        size                 => length $self->{buffer},
        offset               => 8,
        parent               => 0,
    );
    weaken $self->{root};
    my $fsize = length $self->{buffer};
    print "Buffer size is $fsize\n" if $self->{DEBUG};
    $self->ParseSidContainer( $self->{root}->node, 0, $fsize );
    print "Found $self->{atom_count} atoms.\n" if $self->{DEBUG};
    $self->DumpTree( $self->{DEBUGDUMPFILE} )  if $self->{DEBUG} > 1;
}

sub WriteFile {
    my ( $self, $outfile ) = @_;
    open( my $outfh, '>', $outfile ) or croak "Cannot open output $outfile: $!";
    binmode $outfh;
    print $outfh $self->{buffer};
    close $outfh;
}

sub ParseSidContainer {
    my ( $self, $parent, $posit, $end_posit ) = @_;
    my $pAtom = $parent->getNodeValue() or croak "Cannot get atom from node";
    $posit     = $pAtom->start + $pAtom->offset unless defined $posit;
    $end_posit = $pAtom->start + $pAtom->size   unless $end_posit;
    while ( $posit < $end_posit ) {
        my $atom = iTunes::Sid::Atom->new(
            parent               => $parent,
            rbuf                 => \$self->{buffer},
            read_buffer_position => $posit
        );
        print $atom->type, " at $posit size ", $atom->size, "\n"
          if $self->{DEBUG};
        last unless $atom->size > 7;    # sanity check
        $self->{atom_count}++;
        if ( $atom->isContainer() ) {
            if( $sid_types{$atom->type} ) {
                $self->{meta}->{sid_type} = $sid_types{$atom->type};
                print "Sid type is ", $atom->type, "\n" if $self->{DEBUG};
            }
            $self->ParseSidContainer(
                $atom->node,
                $posit + 20,
                $posit + $atom->size - 20
            );
        }
        else {
            print( "done with noncontainer atom of atom of type ",
                $atom->type, "\n" )
              if $self->{DEBUG};
        }
        $posit += $atom->size;
    }
}

sub FindAtomNonheaderData {
    my ( $self, $type ) = @_;
    my @a = $self->FindAtom($type) or return;
    my @data = map { substr $_->data, 4 } @a;
    return @data if wantarray;    # DWIM
    return unless scalar @data > 0;
    return $data[0];
}

sub sid_type { return shift->{meta}->{sid_type} }

sub AtomTree {
    my ($self) = @_;
    return $self->{root}->AtomTree();
}

sub DumpTree {
    my ( $self, $outfile ) = @_;
    if ( $outfile and open( my $dumpfh, ">$outfile" ) ) {
        print $dumpfh $self->AtomTree();
        close $dumpfh;
    }
    else { 
        print $self->AtomTree();
    }
}


=head1 B<NAME>

=over 4

iTunes::Sid - Apple iTunes sid* database file interface

=back

=head1 B<SYNOPSIS>

=over 4

    
=back

=head1 B<DESCRIPTION>

=over 4

    This module allows reading and writing od Apple iTunes type sid* databases,
    including the sidb and sidd files used by iTunes.

=back

=head1 B<METHODS>

=over 4

=item B<new>

    my $sid = iTunes::Sid( file => "sidb" );
    
    Create an iTunes:: Sid object. The file => $filename named argument specifies a 
    data file to be read. 
    
=item B<DESTROY>

    Not to be called directly-- this cleans up circular references, if any.
    
=item B<ReadFile>

    Read a file in for parsing.
    
=item B<ParseBuffer>

    Parse the data in the buffer.
    
=item B<WriteFile>

    Write the (possible modified) file to the filename given.


=item B<ParseSidContainer>

    Parse a container in the buffer position given.
    
=item B<FindAtomNonheaderData>

    Return the data in the atom after its typical 4-byte size, 4-byte type, and 
    12-byte version number fields.

=item B<sid_type> 

    Return the iTunes::Sid file type (sidb or sidd, etc).

=item B<AtomTree>

    Debugging: make an html tree structure for the Sid.
    
=item B<DumpTree>

    Debugging: dump data tree to a file.

=back

=head1 B<SEE ALSO>

=over 4

=item B<Audio::M4P::QuickTime> 

=item B<iTunes::Sid::Atom>

=back

=head1 B<AUTHOR>

=over 4

William Herrera ( B<wherrera@skylightview.com> ). 

=back

=head1 B<SUPPORT> 

=over 4

Questions, feature requests and bug reports should go to <wherrera@skylightview.com>.

=back

=head1 B<Notes>
                                                
=head1 B<NOTES>

    This package is fully legal in all countries, but certain reasonable uses of
    this package may involve a decryption of files which may not be fully legal 
    in some countries.  As regards to the unfortunate U.S. Digital Millenum 
    Copyright Act, that law states in section 102, part (f):

   -----------------------------------------------------------------------
     `(f) REVERSE ENGINEERING- (1) Notwithstanding the provisions of subsection
          (a)(1)(A), a person who has lawfully obtained the right to use a copy 
          of a computer program may circumvent a technological measure that 
          effectively controls access to a particular portion of that program 
          for the sole purpose of identifying and analyzing those elements of 
          the program that are necessary to achieve interoperability of an 
          independently created computer program with other programs, and that 
          have not previously been readily available to the person engaging 
          in the circumvention, to the extent any such acts of identification 
          and analysis do not constitute infringement under this title.

          `(2) Notwithstanding the provisions of subsections (a)(2) and (b), 
          a person may develop and employ technological means to circumvent a 
          technological measure, or to circumvent protection afforded by a 
          technological measure, in order to enable the identification and 
          analysis under paragraph (1), or for the purpose of enabling 
          interoperability of an independently created computer program with 
          other programs, if such means are necessary to achieve such 
          interoperability, to the extent that doing so does not constitute 
          infringement under this title.

          `(3) The information acquired through the acts permitted under 
          paragraph (1), and the means permitted under paragraph (2), may be 
          made available to others if the person referred to in paragraph (1) 
          or (2), as the case may be, provides such information or means solely 
          for the purpose of enabling interoperability of an independently 
          created computer program with other programs, and to the extent 
          that doing so does not constitute infringement under this title or 
          violate applicable law other than this section.

         ----------------------------------------------------------------------

    This portion of the DMCA clearly allows usage of protected content to allow 
    compatibility beween Linux and other systems.  It is our belief that, since 
    this package and other (so far unreleased) Perl code are primarily designed 
    by to allow Linux, Solaris, and Unix systems to achieve interoperability 
    with iTunes and the iTunes Music Store, they ARE legal under the DMCA. We 
    are, however, a bit concerned about the word "solely" in the text above, 
    since this package works under OS X and Windows as well as Linux. Thus, 
    the release of certain other code updates to Linux software for the CPAN 
    iTMS_Client and M4P packages is undone to date (May 2008).
    
    (IANAL--advice from any freedom-loving law professors is solicited :-).
    
    In the meantime, see the COPYRIGHT below.


=head1 B<COPYRIGHT>

=over 4

    Copyright (c) 2008 William Herrera. All rights reserved.  
  
    Licensing Terms

    a) The terms of Perl itself, plus the following:

    b) UNDER NO CIRCUMSTANCES CAN THIS CODE BE USED FOR CIRCUMVENTION OF ANY 
    TECHNOLOGICAL MEASURE WHICH EFFECTIVELY CONTROLS A PROTECTED MEDIA WORK 
    UNDER THE DCMA (USA, 1998) OR EU COPYRIGHT DIRECTIVE (EUCD, ARTICLE 6, 
    OF 2001), UNDER ANY OPERATING PLATFORM SUPPORTED BY THE APPLE COMPUTER 
    CORPORATION FOR ITS ITUNES OR IPOD PLAYER SOFTWARE IN ANY APPLE CORPORATION 
    DISTRIBUTED BINARY FORMAT OF ITUNES FOR THE PLATFORM UNDER WHICH THAT MEDIA 
    IS TO BE PLAYED. AS OF 2008, PROHIBITED PLATFORMS INCLUDE THE IPOD, IPHONE, 
    APPLE OS X, AND MICROSOFT WINDOWS, BUT NOT LINUX, BSD, OR SOLARIS.  UNDER NO 
    CIRCUMSTANCES CAN THE AUTHOR(S) OF THIS CODE BE HELD LIABLE FOR ANY 
    INFRINGEMENT INVOLVING THE PROHIBITED PLATFORMS ABOVE.

    c) Use, storage, or distribution of this code implies that you accept that 
    its intended purpose is legal and legitimate under any applicable US or EU 
    law, as above, and agree that any and all risk as to the quality, 
    performance, and legality of this code lies with you.
    
=back

=cut

1;

