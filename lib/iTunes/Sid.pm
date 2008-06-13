package iTunes::Sid;

use strict;
use warnings;
use Carp qw( carp croak );

use Digest::MD5;
use Crypt::Rijndael;
use Crypt::AppleTwoFish;
use Scalar::Util qw( weaken );

use if ( $^O ne 'MSWin32' and $^O ne 'Darwin' ), 'Win32::Registry::File';
use if $^O eq 'MSWin32', 'Win32::TieRegistry';
use if $^O eq 'MSWin32', 'Win32::DriveInfo';

use iTunes::Sid::Atom;

our $VERSION = '0.02_01';
our $DEBUG   = 0;

#------------- useful constants --------------------#

my $sid_version_prefix_size = 12;
my %sid_version_ok = ( 0x60002 => 1 );

#-------------- documented public functions ------------------------#

sub check_encrypted_sid {
    my ($rbuf) = @_;
    my $version = unpack "N", substr $$rbuf, 0, 4;
    return $sid_version_ok{$version};
}

sub encrypt_aes128 {
    my ( $buf, $key, $iv ) = @_;
    $key = get_sid_key() unless $key and $key ne 'FIND';
    $iv = get_sid_iv() unless $iv;

    my $alg = Crypt::Rijndael->new( $key, Crypt::Rijndael::MODE_CBC );
    $alg->set_iv($iv);
    $buf = $alg->encrypt($buf);

    return $buf;
}

sub decrypt_aes128 {
    my ( $buf, $key, $iv ) = @_;
    $key = get_sid_key() unless $key and $key ne 'FIND';
    $iv = get_sid_iv() unless $iv;
    $buf = substr $buf, 4;

    my $alg = Crypt::Rijndael->new( $key, Crypt::Rijndael::MODE_CBC );
    $alg->set_iv($iv);
    $buf = $alg->decrypt($buf);
    trim_head_nulls( \$buf );

    if ( iTunes::Sid::Atom::isRootAtomType( substr $buf, 4, 4 ) ) {
        return $buf;
    }
    else {
        carp("Bad aes128 sid decrypt with key $key, iv $iv");
        return;
    }
}

sub get_sid_key {
    my $mac = shift || _get_hardware_data_string();
    my $key = q{};
    for my $i ( 0 .. 15 ) {
        my $byte = ord substr( $mac, $i % 6, 1 );
        my $left_side =
          ( ( $i * 0x3BB000 + 0x3BB0 * $byte + 0x7769C46 ) * 0x84DB7605 )
          >> 0x2F;
        $key .= chr( ( $left_side * 0x5C + $byte * 0xB0 + 0x46 ) & 0xFF );
    }
    return $key;
}

sub get_sid_iv {

    # iTunes 7 default ???
    return "\x2C\x67\xD5\xC1\x0C\xF4\x27\x3D\xD4\x06\xCE\x0F\x8F\xD0\x42\xA6";
}

#--- functions that will likely change with new iTunes releases ----#

sub _random_bytes {
    my $num_wanted = shift;
    srand(time);
    my $str = '';
    while ( 1 .. $num_wanted ) {
        $str .= chr rand(255);
        return $str;
    }
}

sub _drms_directory {
    my $home_dir = $ENV{APPDATA} || $ENV{HOME} || q{~};
    my $sPfix = ( $^O eq 'MSWin32' ) ? q{} : q{.};
    my $dirSep = q{/};
    return $home_dir . $dirSep . $sPfix . $dirSep;
}

sub _trim_head_nulls {
    my ($rbuf) = @_;
    $$rbuf =~ s/^(\x00\x00\x00\x00)+//;
    return $rbuf;
}

sub _fix_tail_trash {
    my ($rbuf) = @_;

    return $rbuf;
}

sub _get_hardware_data_string {
    my ($iTunes_platform) = @_;

    if ( $iTunes_platform eq "Darwin" ) {
        my $mac_address = '00-00-00-00-00-00';

        # MAC address should work ok
        # Try to get MAC from parsing text produced by running ifconfig.
        # This will fail if this cannot run and display a MAC address.
        my $parse_text = `ifconfig`;
        $parse_text =~
          m/^.+( ((?:(\d{1,2}|[a-fA-F]{1,2}){2})(?::|-*)){6} ) /xms;
        if ($1) {
            return pack( "C*", map { hex } ( split /-|:/, $1 ) );
        }
        else {
            carp("MAC address not found via ifconfig");
            return;
        }
    }

    if ( $^O eq 'MSWin32' ) {
        my $hw_id_md5 = Digest::MD5->new;
        ( undef, my $drive_serial_number ) = Win32::DriveInfo::VolumeInfo('C');
        $drive_serial_number =~ s/\W//;
        $drive_serial_number = pack "L", hex($drive_serial_number);
        $hw_id_md5->add("cache-controlEthernet");

        my $md5 = Digest::MD5->new;
        $md5->add( substr( $drive_serial_number, 0, 4 ) );
        my $ds_digest = $md5->digest;
        $hw_id_md5->add( substr $ds_digest, 0, 4 );
        $hw_id_md5->add(
            _registry_info_1K_MD5(
                "LMachine\\HARDWARE\\DESCRIPTION\\System\\SystemBiosVersion", 0
            )
        );
        $hw_id_md5->add(
            _registry_info_1K_MD5(
"LMachine\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\ProcessorNameString",
                1
            )
        );
        $hw_id_md5->add(
            _registry_info_1K_MD5(
"LMachine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ProductId",
                1
            )
        );
        return substr $hw_id_md5->digest, 0, 6;
    }

    # TODO:
    # Linux, BSD, or Solaris with a Windows partition readable?
    # see if we can find a Windows registry to read
    # need to get drive serial number for the Windows partition as well

    return;
}

sub _registry_info_1K_MD5 {
    my ( $registry_key, $withnull ) = @_;
    my $val = $Registry->{$registry_key};
    if ($withnull) {
        $val .= "\x00";
    }
    my $md5 = Digest::MD5->new;
    $md5->add($val);
    my $digst = $md5->digest;
    return substr $digst, 0, 4;
}

sub _find_sid {
    my ($sid) = @_;
    my $darwin_sid = "/Users/Shared/SC Info/$sid";
    my $windows_partial_sid =
      "/Application Data/Apple Computer/iTunes/SC Info/$sid";
    my $windows_sid = $ENV{ALLUSERSPROFILE} . $windows_partial_sid;

    return $darwin_sid  if -f $darwin_sid;
    return $windows_sid if -f $windows_sid;

    # do a find, hoping we have a Windows or Darwin drive mounted for find
    return unless $sid =~ m/([\w\d\-\_\.\s]+)/;    # taint elimination
    $sid = $1;
    my @lines = `find / -name $sid`;
    my @results = grep { m|$darwin_sid| } @lines;
    if ( scalar @results ) {
        return $results[0];
    }
    @results = grep { m|$windows_partial_sid| } @lines;
    if ( scalar @results ) {
        return $results[0];
    }
    return;
}

no bigint;

#----------------- class methods ------------------------------#

sub new {
    my ( $class, %args ) = @_;
    my $self = {};
    bless( $self, $class );
    foreach my $k (qw( DEBUG DEBUGDUMPFILE file key iv)) {
        $self->{$k} = $args{$k} if exists $args{$k};
    }
    $self->{meta} = {};
    $self->{DEBUG} = 0 unless exists $self->{DEBUG};
    if ( exists $self->{file} ) {
        if ( $self->{file} eq 'FINDSCINFOSIDB' ) {
            $self->{file} = _find_sid('SC INFO.sidb');
        }
        elsif ( $self->{file} eq 'FINDSCINFOSIDD' ) {
            $self->{file} = _find_sid('SC INFO.sidd');
        }
        $self->ReadFile( $self->{file}, $self->{key}, $self->{iv} );
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
    my ( $self, $infile, $key, $iv ) = @_;
    open( my $infh, '<', $infile ) or croak("Cannot open input $infile: $!");
    binmode $infh;
    read( $infh, $self->{buffer}, -s $infile ) or croak("Bad file read: $!");
    close $infh;
    if ($key) {
        $self->key($key);
        $self->iv($iv);
        $self->decrypt();
    }
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
    open( my $outfh, '>', $outfile )
      or croak "Cannot open output $outfile: $!";
    binmode $outfh;
    print $outfh $self->{buffer};
    close $outfh;
}

sub WriteFileEncrypted {
    my ( $self, $outfile ) = @_;
    open( my $outfh, '>', $outfile )
      or croak "Cannot open output $outfile: $!";
    binmode $outfh;
    $self->encrypt();
    print $outfh $self->{encrypted_buffer};
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
            if ( $atom->isRootAtomType() ) {
                $self->{meta}->{sid_type} = $atom->type;
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

        # do not parse any random garbage added to make right length for AES
        # nothing after the root currently counts
        last if $atom->isRootAtomType();
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

sub SidType { return shift->{meta}->{sid_type} }

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

sub FindAtom {
    my ( $self, $type ) = @_;
    my @atoms =
      grep { $type and $_->type and $_->type =~ /$type$/i }
      @{ $self->{root}->getAllRelatives() };
    return @atoms if wantarray;
    return unless scalar @atoms > 0;
    return $atoms[0];
}

sub key {
    my ( $self, $newkey ) = @_;
    $self->{key} = $newkey if defined $newkey;
    if ( !$self->{key} or $self->{key} eq 'FIND' ) {
        $self->{key} = get_sid_key();
    }
    return $self->{key};
}

sub iv {
    my ( $self, $newiv ) = @_;
    $self->{iv} = $newiv if defined $newiv;
    if ( !$self->{iv} or $self->{iv} eq 'FIND' ) {
        $self->{iv} = get_sid_iv();
    }
    return $self->{iv};
}

sub encrypt {
    my ($self) = @_;

    # following iTunes, should pad the itgr atom with random waste to make size
    # equal to a (multiple of 32 minus 12), to make Rijndael happy
    # with the buffer size after 12 null bytes are added in front

    my $length_with_12 = length $self->{buffer} + 12;
    my $planned_final_length = $length_with_12 + 16 - ( $length_with_12 % 16 );
    my $bytes_to_add = _random_bytes( $planned_final_length - $length_with_12 );
    $self->{buffer} = $self->{buffer} .= $bytes_to_add;
    $self->{meta}->{filesize} = length $self->{buffer};

    # add 12 nulls to the header
    $self->{encrypted_buffer} = ( "\x00" x 12 ) . $self->{buffer};

    $self->{encrypted_buffer} =
      encrypt_aes128( $self->{encrypted_buffer}, $self->key, $self->iv );
    return $self->{encrypted_buffer};
}

sub decrypt {
    my ($self) = @_;
    $self->{buffer} = decrypt_aes128( $self->{buffer}, $self->key, $self->iv );
    $self->_trim_after_itgr();
    return $self->{buffer};
}

sub _trim_after_itgr {
    my ($self) = @_;
    my @itgr_atoms   = $self->FindAtom('itgr') or return;
    my $last_itgr    = $itgr_atoms[ scalar(@itgr_atoms) - 1 ];
    my $cut_position = $last_itgr->start + $last_itgr->size;
    $self->{buffer} = substr( $self->{buffer}, 0, $cut_position );
}

=head1 B<NAME>

=over 4

iTunes::Sid - Apple iTunes SC Info common user database file interface

=back

=head1 B<SYNOPSIS>

=over 4

    
=back

=head1 B<DESCRIPTION>

=over 4

    This module allows reading and writing of Apple iTunes type sid* databases,
    including the sidb and sidd files used by iTunes for storage of keys and 
    certificates.

=back


=head2 Why "Sid.pm" as a module name?

This Apple database format is not publicly documented.  "iTunes::SC Info" 
might have been used as a name, but we can't use spaces in module names.  
The old DOS type 3-digit extension of "SC_Info/SC Info.sidb" and 
"SC_Info/SC Info.sidd" is "sid," so that was used.


=head1 B<METHODS>

=over 4

=item B<new>

    my $sid = iTunes::Sid( file => "sidb", $key => 'FIND', $iv => 'FIND'  );
    
    Create an iTunes::Sid object. The file => $filename named argument specifies a 
    data file to be read. The $key and $iv arguments are for decryption, if needed.
    
=item B<DESTROY>

    Not to be called directly-- this cleans up circular references, if any.
    
=item B<ReadFile>

    Read a file in for parsing.
    
=item B<ParseBuffer>

    Parse the data in the buffer.
    
=item B<WriteFile>

    $sid->WriteFile( file => "sidb2", $key => 'FIND', $iv => 'FIND'  );
    Write the (possibly modified) file to the filename given. $key and $iv
    are as in the new() method.

=item B<WriteFileEncrypted>

    $sid->WriteFileEncrypted( file => "sidb2", $key => 'FIND', $iv => 'FIND'  );
    Write the (possibly modified) file to the filename given.  The file is encrypted
    before writing (default is to use the key and iv used to decrypt originally).  
    
    
=item B<ParseSidContainer>

    Parse a container in the buffer position given.
    
=item B<FindAtomNonheaderData>

    Return the data in the atom after its typical 4-byte size, 4-byte type, and 
    12-byte version number fields.

=item B<SidType> 

    Return the iTunes::Sid file type (sidb or sidd, etc).

=item B<AtomTree>

    Return an html tree structure for the Sid.
    
=item B<DumpTree>

    Dump data tree to a file, or to standard output by default.

=item B<FindAtom>

    my @list = $sid->FindAtom("key ");

    Find any or all atoms in the sid of a given type.

=item B<encrypt>


=item B<decrypt>

=back

=head1 PUBLIC FUNCTIONS (function interfaces only)

=over 4

=item B<check_encrypted_sid>

    my $ok_check = check_encrypted_sid( $encrypted_sid_buffer );
    
    Check an encrypted sid (in memory) for correct form to attemy decryption.

=item B<process_encrypted>

    process_encrypted( $buf_ref, $key, $iv );
    process_encrypted( $buf_ref, 'FIND', 'FIND' );
    
    Process the memory referred to by the scalar reference $buf_ref to
    decrypt it using $key and $iv.  Attempt to find $key and $iv if 'FIND'
    is specified, using iTunes 7 algorithms and local machine data.
    

=item B<encrypt_aes128>

    encrypt_aes128( $buf, $key, $iv );
    
    Using AES (Rijndael) in CBC mode, encrypt $buf with key of $key (128 bits) 
    and iv $iv.  'FIND' means try to locate the key and IV on the local machine
    using iTunes 7 type algorithms.

=item B<decrypt_aes128>

    decrypt_aes128( $buf, $key, $iv );
    
    Using AES (Rijndael) in CBC mode, decrypt $buf with key of $key (128 bits) 
    and iv $iv.  'FIND' means try to locate the key and IV on the local machine
    using iTunes 7 type algorithms.

    Return a decrypted buffer on success, undef otherwise,

=item B<get_sid_key>

    my $key = get_sid_key();
    
    Using iTunes / QuickTime based algorithms based on characteristics of the
    local machine, try to calculate the key and iv for cryptography .
    
=item B<get_sid_iv>

    my $iv = get_sid_iv();
    
    Return the default iTunes / QuickTime based iv for SC Info databases.

=item B<iv>

    Get or set iv.

=item B<key>

    Get or set key.

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
                                               
=head1 B<NOTES>

=head2 Regarding the US DMCA Law

    The U.S. Digital Millenum Copyright Act states in section 102, part (f):

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

=head2 Our take on why this code is an example of free and protected speech:

    The portion of the DMCA quoted above allows usage of protected content to 
    enable interoperability beween Linux and other systems.  Therefore, since 
    this package and other (so far unreleased) Perl code are primarily designed 
    to allow Linux, Solaris, and Unix systems to achieve interoperability with 
    iTunes and the iTunes Music Store, they ARE legal under the DMCA. We are 
    somewhat concerned about the word "solely" in the text above, since this 
    package works under OS X and Windows as well as Linux.  For that reason, 
    please also see the COPYRIGHT below.


=head1 B<COPYRIGHT>

=over 4

    Copyright (c) 2008 William Herrera. All rights reserved.  
  
    Licensing Terms

    a) The terms of Perl itself, plus the following:

    b) UNDER NO CIRCUMSTANCES CAN THIS CODE BE USED FOR CIRCUMVENTION OF ANY 
    TECHNOLOGICAL MEASURE WHICH EFFECTIVELY CONTROLS A PROTECTED MEDIA WORK 
    UNDER THE DCMA (USA, 1998) OR EU COPYRIGHT DIRECTIVE (EUCD, ARTICLE 6, 
    OF 2001), UNDER ANY OPERATING SYSTEM PLATFORM SUPPORTED BY APPLE COMPUTER 
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
