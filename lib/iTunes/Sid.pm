package iTunes::Sid;

use strict;
use warnings;

use File::Path;
use Digest::MD5;
use File::Basename;
use Crypt::Rijndael;
use File::Find::Rule;
use Crypt::AppleTwoFish;
use Parse::Win32Registry;
use Carp qw( carp croak );
use List::Util qw( first );
use Scalar::Util qw( weaken );

use iTunes::Sid::Atom;

our $VERSION = '0.40';

#-----------  determines whether data is saved to .drms by default -----------#

my $auto_save_guid_and_mac_in_drms_dir = 1;
my $auto_read_guid_and_mac_in_drms_dir = 1;

#--------------- package defaults for searches ----------------#

# this is often wrong, but may sugggest Linux defaults for others
# to adapt to a typical dual boot setup, may need to substitute
#     'disk-2' for 'disk-1' or '/mnt' for '/media', etc.
my @default_SCInfo_directory = (
    '/media/disk-1/ProgramData/Apple Computer/iTunes/SC Info/',
    '/media/disk-1/Documents and Settings/Application Data/Apple Computer/iTunes/SC Info',
    '/ProgramData/Apple Computer/iTunes/SC Info/',
    '/Documents and Settings/All Users/Application Data/Apple Computer/iTunes/SC Info',    
);

#------------------- useful constants -----------------------------#

my $sid_version_prefix_size = 12;
my %sid_version_ok = ( 0x60002 => 1 );

#-------------- documented public functions ------------------------#

sub check_encrypted_sid {
    my ($rbuf) = @_;
    my $version = unpack "N", substr $$rbuf, 0, 4;
    return $sid_version_ok{$version};
}

sub _random_bytes {
    my $num_wanted = shift;
    srand(time);
    my $str = '';
    while ( 1 .. $num_wanted ) {
        $str .= chr rand(255);
    }
    return $str;
}

sub _decode_16_bytes {
    my ( $bytes, $key ) = @_;
    carp("wrong key length") unless length $bytes == 16;
    my $alg = Crypt::Rijndael->new( $key, Crypt::Rijndael::MODE_CBC );
    return $alg->decrypt($bytes);
}

#--- functions that will likely change with new iTunes releases ----#

sub get_sid_iv {

    # iTunes 7 default ???
    return "\x2C\x67\xD5\xC1\x0C\xF4\x27\x3D\xD4\x06\xCE\x0F\x8F\xD0\x42\xA6";
}

sub get_sid_key {
    my ($mac) = @_;
    use bigint;
    if ( !$mac or length $mac != 6 ) {
        carp("Bad hwID for mac string");
        return;
    }
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

sub _drms_directory {
    my $home_dir = $ENV{APPDATA} || $ENV{HOME} || q{~};
    my $sPfix = ( $^O eq 'MSWin32' ) ? q{} : q{.};
    my $dirSep = q{/};
    return $home_dir . $dirSep . $sPfix . 'drms' . $dirSep;
}

sub _info_MD5 {
    my ( $val, $withnull ) = @_;
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

    # check the default dir if there is one
    for my $scdir  (@default_SCInfo_directory) {
        my $default_pathname = $scdir . '/' . $sid;
       if ( -f $default_pathname ) {
            return $default_pathname ;
        }
    }

    my $darwin_sid_dir = "/Users/Shared/SC Info/";
    my $darwin_sid     = $darwin_sid_dir . $sid;

    my $windows_sid_dir = "/Apple Computer/iTunes/SC Info/";
    my $windows_sid     = $windows_sid_dir . $sid;

    my $dir_filter = qr{$darwin_sid_dir|$windows_sid_dir};
    my @sid_dirs =
      File::Find::Rule->directory()->maxdepth(8)->name($dir_filter)->in('/');
    my @sids = File::Find::Rule->file()->name($sid)->in(@sid_dirs);
    if ( scalar @sids ) {
        push @default_SCInfo_directory, dirname( $sids[0] );
        return $sids[0];
    }
    return;
}

sub _trim_head_nulls {
    my ($rbuf) = @_;
    $$rbuf =~ s/^(\x00\x00\x00\x00)+//;
    return $rbuf;
}

#----------------- class methods ------------------------------#

sub new {
    my ( $class, %args ) = @_;
    my $self = {};
    bless( $self, $class );
    foreach my $k (qw( DEBUG DEBUGDUMPFILE file key iv mac 
      regdata iTunes_platform scinfo_directory )) {
        $self->{$k} = $args{$k} if exists $args{$k};
    }
    $self->{meta} = {};
    $self->{DEBUG} = 0 unless exists $self->{DEBUG};
    push @default_SCInfo_directory, $self->{scinfo_directory}
      if exists $self->{scinfo_directory};
    if ( exists $self->{file} ) {
        if ( $self->{file} eq 'SCINFOSIDB' ) {
            $self->{file} = _find_sid('SC Info.sidb');
        }
        elsif ( $self->{file} eq 'SCINFOSIDD' ) {
            $self->{file} = _find_sid('SC Info.sidd');
        }
        $self->ReadFile( $self->{file}, $self->key(), $self->iv() );
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
    open( my $infh, '<', $infile )
      or croak("Cannot open input $infile: $!");
    binmode $infh;
    read( $infh, $self->{buffer}, -s $infile )
      or croak("Bad file read: $!");
    close $infh;
    if ($key) {
        $self->key($key);
        $self->iv($iv);
        $self->decrypt() or croak "bad decrypt";
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
    print "Pre-endtrim buffer size is $fsize\n" if $self->{DEBUG};
    $self->ParseSidContainer( $self->{root}->node, 0, $fsize );
    $self->_trim_after_itgr();
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
    my $pAtom = $parent->getNodeValue()
      or croak "Cannot get atom from node";
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

sub _save_mac_to_drms_dir {
    my ($self)    = @_;
    my $dest_file = _drms_directory . 'mac';
    my $mac       = $self->mac;
    if ($mac) {
        if ( open my $fh, '>', $dest_file ) {
            binmode $fh;
            print "saving \"$mac\" to file $dest_file\n" if $self->{DEBUG};
            print $fh "mac=$mac";
            close $fh;
        }
        else {
            carp("Cannot open $dest_file for writing: $!");
        }
    }
    else {
        carp("Cannot find MAC to write to file $dest_file");
    }
    return $mac;
}

sub _read_mac_from_drms_dir {
    my ($self) = @_;
    my $mac;
    my $in_file = _drms_directory . 'mac';
    if ( -f $in_file and open my $fh, '<', $in_file ) {
        binmode $fh;
        my $s = <$fh>;
        close $fh;
        if ( $s =~ m/^mac=(.+)/ ) {
            $mac = $1;
            $self->{mac} = $mac;
            print "got mac from file $in_file\n" if $self->{DEBUG};
        }
        else {
            carp("mac not readable: file first line should be: mac=.\{6\}");
        }
    }
    return $mac;
}

sub FindAtom {
    my ( $self, $type ) = @_;
    return unless $self->{root};
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
#    $self->{mac} ||= $self->_get_hardware_data_string();
    if ( !$self->{key} or $self->{key} eq 'FIND' ) {
        $self->{key} = get_sid_key( $self->mac() );
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

sub mac {
    my ( $self, $newmac ) = @_;
    $self->{mac} = $newmac if defined $newmac;
    if ( !$self->{mac} ) {
        if($auto_read_guid_and_mac_in_drms_dir) {
            $self->{mac} = $self->_read_mac_from_drms_dir();
        }
        if ( !$self->{mac} ) {
            $self->{mac} = $self->_get_hardware_data_string();
            if ( $self->{mac} and $auto_save_guid_and_mac_in_drms_dir ) {
                $self->_save_mac_to_drms_dir( $self->{mac} );
            }
        }
        if ( !$self->{mac} ) {
            carp("Cannot locate mac / hardware ID string: $!");
        }
    }
    return $self->{mac};
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
    my $skey = get_sid_key( $self->mac() );
    my $alg = Crypt::Rijndael->new( $skey, Crypt::Rijndael::MODE_CBC );
    $alg->set_iv( $self->iv() );
    $self->{encrypted_buffer} = alg->encrypt( $self->{encrypted_buffer} );
    return $self->{encrypted_buffer};
}

sub decrypt {
    my ($self) = @_;
    my $buf  = substr $self->{buffer}, 4;
    my $skey = get_sid_key( $self->mac() );
    my $alg  = Crypt::Rijndael->new( $skey, Crypt::Rijndael::MODE_CBC );
    $alg->set_iv( $self->iv() );
    $buf = $alg->decrypt($buf);
    _trim_head_nulls( \$buf );
    my $root_atom_type = substr $buf, 4, 4;
    if ( iTunes::Sid::Atom::isRootAtomType( $root_atom_type) ) {
        $self->{buffer} = $buf;
        return $buf;
    }
    else {
        carp( "Bad aes128 sid decrypt with key ",
            $self->key, " iv ", $self->iv, " result $root_atom_type" );
        return;
    }
}

# if sid has a version atom, return as 32 bit big endian integer
sub sid_version {
    my ($self) = @_;
    my $vers = $self->FindAtom('vers');
    if ($vers) {
        return $vers->Data32();
    }
    return;
}

sub _get_hardware_data_string {
    my ($self) = @_;
    return $self->{mac} if $self->{mac};

    my $hardware_string = "\x00\x00\x00\x00\x00\x00";
    
    my $platform = $self->{platform};
    if ( $platform and $platform eq "Darwin" ) {

        # OS X was the iTunes platform that made the SC Info files we will use,
        # so the ethernet MAC address should work ok
        # Try to get MAC from parsing text produced by running ifconfig.
        # This will fail if this cannot run and display a MAC address.
        my $parse_text = `ifconfig`;
        $parse_text =~
          m/^.+( ((?:(\d{1,2}|[a-fA-F]{1,2}){2})(?::|-*)){6} ) /xms;
        if ($1) {
            $hardware_string = pack( "C*", map { hex } ( split /-|:/, $1 ) );
        }
        else {
            carp("MAC address not found via ifconfig");
            return;
        }
    }
    else {

        # Default case: MSWin32 was the iTunes platform that made SC Info files
        # Running Linux, BSD, or Solaris with a Windows partition mounted?
        # If so, will need to get the registry data from a "regdata" file
        my ( $volume, $bios, $processor, $ProductID );
        if ( open my $infh, '<', $self->{regdata} ) {
            my @lines = <$infh>;
            close $infh;
            for my $s (@lines) {
                $s =~ s/\r|\n//g;
                next unless $s;
                if ( $s =~ /SystemBiosVersion\s.+SZ\s+(\S.+)$/ ) {
                    $bios = $1;
                }
                elsif ( $s =~ /ProcessorNameString\s.+SZ\s+(\S.+)$/ ) {
                    $processor = $1;
                }
                elsif ( $s =~ /ProductId\s.+SZ\s+(\S.+)$/ ) {
                    $ProductID = $1;
                }
                elsif ( $s =~ /Volume Serial Number is\s+(\S+)$/ ) {
                    $volume = $1;
                }
            }
            print "Bios: [ " , $bios , " ]\nCPU: [ ", $processor, " ]\n",
              "Product ID: [ ", $ProductID, " ]\nVolume Serial: [ ", $volume, " ]\n"
              if $self->{DEBUG};
            $bios =~ s/\\0/\x00/g;
            $volume =~ s/-//;
            $volume = pack "L", hex $volume;
            my $hw_id_md5 = Digest::MD5->new;
            $hw_id_md5->add("cache-controlEthernet");
            if ($volume) {
                $hw_id_md5->add(
                    _info_MD5( substr( $volume, 0, 4 ), 0 ) );
            }
            else {
                carp("Cannot find volume serial number");
                return;
            }
            if ($bios) {
                $hw_id_md5->add( _info_MD5( $bios, 0 ) );
            }
            else {
                carp( "Cannot find the bios string from file ",
                    $self->{regdata_file} );
                return;
            }
            if ($processor) {
                $hw_id_md5->add( _info_MD5( $processor, 1 ) );
            }
            else {
                carp( "Cannot find the CPU string from file ",
                    $self->{regdata_file} );
                return;
            }
            if ($ProductID) {
                $hw_id_md5->add( _info_MD5( $ProductID, 1 ) );
            }
            else {
                carp( "Cannot find the Windows software ProductId from file ",
                    $self->{regdata_file} );
                return;
            }
            $hardware_string = substr $hw_id_md5->digest, 0, 6;
        }
    }
    $self->{mac} = $hardware_string;
    print "hwID is: 0x", ( join '', map { sprintf '%02X', $_ }  
      unpack "C*", $hardware_string ), " ( $hardware_string )\n" if $self->{DEBUG};
    return $hardware_string;
}

sub _trim_after_itgr {
    my ($self) = @_;
    my @itgr_atoms = $self->FindAtom('itgr') or return;
    my $last_itgr = $itgr_atoms[ scalar(@itgr_atoms) - 1 ];
    $self->{buffer} = substr( $self->{buffer}, 0, $last_itgr->Ending );
}

sub find_veggie_for_userID {
    my ( $self, $userID ) = @_;
    my $sd = iTunes::Sid->new(
        file => 'SCINFOSIDD',
        key  => 'FIND',
        iv   => 'FIND',
        regdata => $self->{regdata},
    );
    if ( $sd->sid_version() != 0x10001 ) {
        carp("Incompatible SC Info version");
        return;
    }
    my $mac  = $self->mac();
    my @grup = $sd->FindAtom('grup');
    my ( $own_grup, $guid_mac );
    for my $gp (@grup) {
        my $head = $gp->DirectChildren('head')   or next;
        my $guid = $head->DirectChildren('guid') or next;
        $guid_mac = substr $guid->NonVersionData(), 0, 6;
        if ( $mac eq $guid_mac ) {
            $own_grup = $gp;
            last;
        }
        else {
            print "group excluded: mac is $mac, guid data was $guid_mac\n"
              if $self->{DEBUG};
        }
    }
    unless ($own_grup) {
        carp("Cannot find the correct group for guid");
        return;
    }
    my $user =
      first { $_->MainVersion() eq $userID } $own_grup->DirectChildren('user')
      or do {
        carp( "Cannot find proper user to match $userID: found ",
            join "  ",
            map { $_->MainVersion() } $own_grup->DirectChildren('user') );
        return;
      };
    if( $auto_save_guid_and_mac_in_drms_dir and $guid_mac ) {
        my $guid_entry_file = _drms_directory . 'guID';
        if( ! -f $guid_entry_file ) {
            open( my $gfh, '>', $guid_entry_file );
            binmode $gfh;
            print $gfh $guid_mac;
            close $gfh;
        }
    }
    my $usag =
      first { $_->MainVersion == 0x2100003 } $user->DirectChildren('usag')
      or do {
        carp( "Cannot find proper usag to match ",
            0x2100003, " : found ", join "  ",
            map { $_->MainVersion() } $user->DirectChildren('usag') );
        return;
      };
    my $valu       = $usag->DirectChildren('valu');
    my $table_size = $valu->size - 646;
    if ( $valu and $table_size > 100000 ) {
        my $table_bytes = substr $valu->data, 638;
        my @byte_table = split //, $table_bytes;
        my @int_table = unpack "N*", $table_bytes;
        my $veggie = substr $valu->data, 28, 6;
        $self->{veggie_table}->{as_byte}->{$veggie}    = \@byte_table;
        $self->{veggie_table}->{as_integer}->{$veggie} = \@int_table;
        print "Found table for $veggie, contains ", ( scalar @int_table ),
          " integers\n"
          if $self->{DEBUG};
        return $veggie;
    }
    carp("No matching vegetable found");
    return;
}

sub fetch_all_user_keys {
    my ($self) = @_;
    my $sb = iTunes::Sid->new( 
        file    => 'SCINFOSIDB', 
        key     => 'FIND',
        regdata => $self->{regdata},
    );
    my @users = $sb->FindAtom('user');
    for my $usr (@users) {
        my $userID = $usr->MainVersion();
        print "Processing userID $userID\n" if $self->{DEBUG};
        if ( ( $usr->DirectChildren('vers') )->Data32() != 0x10002 ) {
            carp("bad key version");
            next;
        }
        my $veggie = $self->find_veggie_for_userID($userID);
        print "Veggie is $veggie\n" if $self->{DEBUG};
        my @b_keys = $usr->DirectChildren('key ');
        for my $b_key (@b_keys) {
            my $keyID   = $b_key->MainVersion();
            my $keyType = $b_key->DirectChildren('type');
            if ( !$keyType or $keyType->Data32() != 3 ) {
                carp( " Key crypto version compatibility error: version is ",
                    $keyType ? $keyType->Data32 : 'nil' );
                next;
            }
            my $encrypted = ( $b_key->DirectChildren('valu') )->NonVersionData;
            print "Encrypted key $keyID is $encrypted..."
              if $self->{DEBUG};
            my $vg = Crypt::AppleTwoFish->new(
                hwID       => $self->mac(),
                keyID      => $keyID,
                userID     => $userID,
                veggie     => $veggie,
                int_table  => $self->{veggie_table}->{as_integer}->{$veggie},
                byte_table => $self->{veggie_table}->{as_byte}->{$veggie},
                DEBUG      => $self->{DEBUG},
            );

            my @mature_bytes  = $vg->plant_veggies();
            my $key_key       = $vg->harvest_veggies(@mature_bytes);
            my $decrypted_key = _decode_16_bytes( $encrypted, $key_key );
            print "decrypted key is $decrypted_key\n" if $self->{DEBUG};
            $self->{user_drm_keys}->{$userID}->{$keyID} = $decrypted_key;
        }
    }
}

# Write to .drms directory (do not overwrite unless overwrite is ok )
#   as in $sid->write_keys_to_drms_directory( overwrite_ok => 1 );
sub write_all_user_keys_to_drms_dir {
    my ( $self, %args ) = @_;
    my $overwrite_ok = $args{overwrite_ok};
    my $drm_dir      = _drms_directory();
    mkpath($drm_dir);
    while ( my ( $userID, $keys ) = each %{ $self->{user_drm_keys} } ) {
        while ( my ( $keyID, $keyval ) = each %{$keys} ) {
            my $filename = sprintf "%s%08X.%03d", $drm_dir, $userID, $keyID;
            next if -f $filename and !$overwrite_ok;
            print "printing key $keyval to file $filename\n"
              if $self->{DEBUG};
            open my $outf, '>', $filename or do {
                carp(" Cannot open $filename for output: $!");
                next;
            };
            binmode $outf;
            print $outf $keyval;
            close $outf;
        }
    }
}

=head1 NAME

  iTunes::Sid -- Apple iTunes SC Info common user database file interface

=head1 SYNOPSIS

=over 4

=back

=head1 DESCRIPTION

=over 4

  This module allows reading and writing of Apple iTunes type 
  I<SC info.sid> databases, including the sidb and sidd files 
  used by iTunes for storage of keys and certificates.

=back


=head1 METHODS

=over 4

=item B<new>

        my $sid = iTunes::Sid( file => "sidb", $key => 'FIND', $iv => 'FIND'  );
    
        my $sid = iTunes::Sid( file => "sidb", regdata => 'filename', 
                               iTunes_platform => 'Darwin' );
    
    Create an iTunes::Sid object. The file => $filename named argument specifies a 
    data file to be read. The $key and $iv arguments are for decryption, if needed.
    regdata is a pathname of a file containing hardware data for key calculation.
    
    iTunes_platform => 'Darwin'  means to look for an existing OS X installation 
    on the mounted drives.  The default is to look for an accessible Windows 
    partition on which to find the SC Info data.
    
        my $sid = iTunes::Sid( file => 'SCINFOSIDB', regdata => 'filename' );
    
    my $sid = iTunes::Sid( file => 'SCINFOSIDD', regdata => 'filename',
        scinfo_direcory 
          => '/media/windisk/ProgramData/Apple Computer/iTunes/SC Info' );
    
    SCINFOSIDB and SCINFOSIDD are 'magic' file names indicating we should look 
    for the SC Info/Sc Info.sid[b|d] files and open them if found.  scinfo_directory
    is a location to look for the SC Info.sid? files.  Remember to mount the 
    Windows drive first, and take note of its assigned name once mounted.
    
        my $sid = iTunes::Sid( file => "SCINFOSIDB", REGDATAFILE => 'regdata' );

    Read the Sc Info/Sc Info.sidb file using a key calculated from the regdata 
    file created with the following Windows command file, run on the XP or 
    Vista installation for which iTunes created its SC Info files:
    
    ===========================================================================
    @echo off
    rem file get_hwdata.cmd, run as "get_hwdata.cmd > \regdata" from Windows command prompt
    
    REG query "HKLM\HARDWARE\DESCRIPTION\System" /v SystemBiosVersion 

    REG query "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0" /v ProcessorNameString 

    REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" /v ProductId 
    
    DIR C:\Windows\PROTOCOL.INI

    ===========================================================================

    See the examples directory also, and see the LINUX_HOWTO in the examples.
        
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

=item B<mac>

    Get or set hardware ID (the MAC address OR a derived machine signature).

=item B<iv>

    Get or set iv.

=item B<key>

    Get or set key.

=item B<sid_version>

    Version of the sid file, from the vers atom.
    
=item B<find_veggie_for_userID>

    Find the veeggie table and special shuffle case for the key's key.

=item B<fetch_all_user_keys>
 
    Find and decode all the keys in the SC Info.sidb file.
 
=item B<write_all_user_keys_to_drms_dir>
 
    Write all the decoded keys to files in the user's .drms directory 
    file for use by VLC and compatible media players.

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
    

=item B<get_sid_key>

    my $key = get_sid_key( $mac );
    
    Using iTunes / QuickTime based algorithms based on characteristics of the
    local machine, try to calculate the shuffled key for AES cryptography .
    
=item B<get_sid_iv>

    my $iv = get_sid_iv();
    
    Return the default iTunes / QuickTime based iv for SC Info databases.

=back

=head1 LINUX HOWTO 

=over 4

The following is intended for fair use of purchased music by the purchaser, not
for piracy. In order to format the FairPlay keys used by iTunes for use by a 
music player such as VLC under Linux, the keys must be pulled from the 
SC Info.sidb file, translated using information in the SC Info. sidd file, and
then written to a directory where VLC will read the keys for its use.  Note that
such use does B<not> remove the DRM from the purchased music files themselves, 
but makes them far more useable under Linux, without resorting to Wine.

Procedure:

1. Set up a machine for dual boot under the iTunes installation OS (OS X or 
Windows).  One partition is to boot OS X or Windows, another Linux. Make sure 
that your Darwin or NTFS partition is mounted at least for reading!

2A.  (iTunes for Windows) Run the file ./examples/get_hwdata.cmd in the 
     iTunes::Sid /examples directory in this distribution and redirect to a 
     file given as the command's argument, as in

     c:> get_hwdata.cmd c:\regdata

    Then reboot to Linux and mount the windows partion (it should be attached 
    to /media/disk1/ or /media/disk2, etc).  
    
    Run the file ./examples/get_keys_for_vlc.pl (the file pathname on line 10 
    may need to be changed to be directed to the output file of the Windows 
    command file above).

2B. (iTunes for OS X) Dual boot may "just work" since the key is derived 
    from the computer's LAN card MAC address.  If attaching to the OS X 
    machine over a network share, you may get the mac address of the source 
    machine by running ./examples/print_mac.pl and redirecting this to a file, 
    then copying that file to your home directory into a subdirectory called 
    '.drms' and a file called 'mac' in that directory. iTunes::Sid will look 
    for this file, and use it for the mac adddress if it finds that file.  

3.  Run the ./examples/get_keys_for_vlc.pl perl script to allow any DRM-laden
    iTMS purchases to play under VLC or other compatible media players.

    If the above fails, you may be able to run the above under OS X or Windows, 
    and then copy the drms directory and its keys to your linux home directory,
    renaming 'drms' to '.drms' and then run VLC to play music as usual.  (The same 
    must be done if the keys are generated under the /root account-- copy the 
    /root/.drms directory to your home directory).

=back

=head1 SEE ALSO

=over 4

=item B<Audio::M4P::QuickTime> 

=item B<iTunes::Sid::Atom>

=back

=head1 BUGS

=over 4

Initial setup almost requires a dual boot machine.  

Searches for SC Info files are subject to file finding errors. 

No doubt many others.

=back

=head1 AUTHOR

=over 4

William Herrera ( B<wherrera@skylightview.com> ). 

=back

=head1 SUPPORT 

=over 4

Questions, feature requests and bug reports should go to <wherrera@skylightview.com>.

=back
                                               
=head1 NOTES

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
    this package and related Perl code are primarily designed to allow Linux, 
    Solaris, and Unix systems to achieve interoperability with iTunes and the 
    iTunes Music Store, they ARE legal under the DMCA. We are somewhat 
    concerned about the word "solely" in the text above, since this package 
    works under OS X and Windows as well as Linux.  For "solely" that reason, 
    please also see the COPYRIGHT below.


=head1 COPYRIGHT

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

return 1;
