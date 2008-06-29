package iTunes::Sid;

use strict;
use warnings;

use Carp qw( carp croak );
use List::Util qw( first );
use if $^O ne "MSWin32", 'Parse::DMIDecode';
use if $^O ne "MSWin32", 'Sys::Info';
use if $^O ne "MSWin32", 'vars', qw( $Registry );
use if $^O eq 'MSWin32', 'Win32::TieRegistry';
use if $^O eq 'MSWin32', 'Win32::DriveInfo';
use File::Path;
use Digest::MD5;
use File::Basename;
use Crypt::Rijndael;
use File::Find::Rule;
use Crypt::AppleTwoFish;
use Parse::Win32Registry;
use Scalar::Util qw( weaken );

use iTunes::Sid::Atom;

our $VERSION = '0.031';

#------------------- useful constants -----------------------------#

my $sid_version_prefix_size = 12;
my %sid_version_ok = ( 0x60002 => 1 );

#--------------- package defaults for searches ----------------#

my $default_SCInfo_directory = '/media/disk-1/Windows/System32/config/';
my $default_hive_file        = './_REGISTRY_MACHINE_SOFTWARE';

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
        return $str;
    }
}

#--- functions that will likely change with new iTunes releases ----#

sub _drms_directory {
    my $home_dir = $ENV{APPDATA} || $ENV{HOME} || q{~};
    my $sPfix = ( $^O eq 'MSWin32' ) ? q{} : q{.};
    my $dirSep = q{/};
    return $home_dir . $dirSep . $sPfix . 'drms' . $dirSep;
}

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

sub _trim_head_nulls {
    my ($rbuf) = @_;
    $$rbuf =~ s/^(\x00\x00\x00\x00)+//;
    return $rbuf;
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

sub _registry_info_MD5 {
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

    # check the default dir if there is one
    if ($default_SCInfo_directory) {
        my $use_last_dir = $default_SCInfo_directory . '/' . $sid;
        return $use_last_dir if -e $use_last_dir;
    }

    my $darwin_sid = "/Users/Shared/SC Info/$sid";
    my $windows_partial_XP_sid =
      "/Application Data/Apple Computer/iTunes/SC Info/$sid";
    my $windows_partial_Vista_sid = "/Apple Computer/iTunes/SC Info/$sid";
    my $windows_xp_sid    = $ENV{ALLUSERSPROFILE} . $windows_partial_XP_sid;
    my $windows_vista_sid = $ENV{ALLUSERSPROFILE} . $windows_partial_Vista_sid;

    return $darwin_sid        if -f $darwin_sid;
    return $windows_xp_sid    if -f $windows_xp_sid;
    return $windows_vista_sid if -f $windows_vista_sid;

    # do a find, hoping we have a Windows or Darwin drive mounted for find
    return unless $sid =~ m/([\w\d\-\_\.\s]+)/;    # taint elimination
    $sid = $1;
    my @lines = `find / -name $sid`;
    my @results = grep { m|$darwin_sid| } @lines;
    if ( scalar @results ) {
        $default_SCInfo_directory = dirname( $results[0] );
        return $results[0];
    }
    @results =
      grep { m/$windows_partial_XP_sid|$windows_partial_Vista_sid/ } @lines;
    if ( scalar @results ) {
        $default_SCInfo_directory = dirname( $results[0] );
        return $results[0];
    }
    return;
}

sub _get_hive_file {

    # if there is a default file to use, return it
    return $default_hive_file if -f $default_hive_file;

    # Registry search for Windows product ID
    # need a mounted Windows partition or drive in /media/ for this
    my ( $mount_root_dir, $dir_filter, $file_filter );
    if ( $^O eq 'MSWin32' ) {
        $mount_root_dir = "\\";
        $dir_filter     = qr{System Volume Information/_restore.+/snapshot};
        $file_filter    = '_REGISTRY_MACHINE_SOFTWARE';
    }
    else {
        $mount_root_dir = '/media';
        $dir_filter     = 'config';
        $file_filter    = 'SOFTWARE';
    }
    my $software_registry_file;
    my @software_registry_dirs =
      File::Find::Rule->directory()->maxdepth(4)->name($dir_filter)
      ->in($mount_root_dir);
    my @registry_files =
      File::Find::Rule->file()->name($file_filter)->in(@software_registry_dirs);
    if ( scalar @registry_files ) {
        return $registry_files[0];
    }
    else {
        carp("Cannot find the current Windows software registry file");
        return;
    }
}

sub _decode_16_bytes {
    my ( $bytes, $key ) = @_;
    carp("wrong key length") unless length $bytes == 16;
    my $alg = Crypt::Rijndael->new( $key, Crypt::Rijndael::MODE_CBC );
    return $alg->decrypt($bytes);
}

no bigint;

#----------------- class methods ------------------------------#

sub new {
    my ( $class, %args ) = @_;
    my $self = {};
    bless( $self, $class );
    foreach my $k (qw( DEBUG DEBUGDUMPFILE file key iv mac)) {
        $self->{$k} = $args{$k} if exists $args{$k};
    }
    $self->{meta} = {};
    $self->{DEBUG} = 0 unless exists $self->{DEBUG};
    if ( exists $self->{file} ) {
        if ( $self->{file} eq 'SCINFOSIDB' ) {
            $self->{file} = _find_sid('SC INFO.sidb');
        }
        elsif ( $self->{file} eq 'SCINFOSIDD' ) {
            $self->{file} = _find_sid('SC INFO.sidd');
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
    $self->{mac} ||= $self->_get_hardware_data_string();
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
    if ( !$self->{iv} ) {
        $self->{mac} = $self->_get_hardware_data_string();
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
    if ( iTunes::Sid::Atom::isRootAtomType( substr $buf, 4, 4 ) ) {
        $self->{buffer} = $buf;
        return $buf;
    }
    else {
        carp( "Bad aes128 sid decrypt with key ",
            $self->key, " iv ", $self->iv );
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
    my ( $self, $iTunes_platform, $mount_root_dir ) = @_;
    return $self->{mac} if $self->{mac};
    $iTunes_platform ||= 'MSWin32';
    my $hardware_string = "\x00\x00\x00\x00\x00\x00";

    if ( $iTunes_platform eq "Darwin" ) {

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
    elsif ( $^O eq "MSWin32" ) {
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
            _registry_info_MD5(
                "LMachine\\HARDWARE\\DESCRIPTION\\System\\SystemBiosVersion", 0
            )
        );
        $hw_id_md5->add(
            _registry_info_MD5(
"LMachine\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\ProcessorNameString",
                1
            )
        );
        $hw_id_md5->add(
            _registry_info_MD5(
"LMachine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ProductId",
                1
            )
        );
        $hardware_string = substr $hw_id_md5->digest, 0, 6;
    }
    else {

        # Default case: MSWin32 was the iTunes platform that made SC Info files
        # Running Linux, BSD, or Solaris with a Windows partition mounted?
        # If so, see if we can find a Windows registry to read (slow process)
        # Also need various hardware stuff not in a fixed registry file
        my $hw_id_md5 = Digest::MD5->new;
        $hw_id_md5->add("cache-controlEthernet");

        # drive serial number
        my $drive_serial;
        my @lines = `hdparm -I /dev/sda`;
        my @d_txt = grep { m/Serial Number/ } @lines;
        if ( @d_txt and $d_txt[0] =~ m/:\s*([a-zA-Z\-\s\d]+)/ ) {
            $drive_serial = $1;
            $hw_id_md5->add( _info_MD5( substr( $drive_serial, 0, 4 ), 0 ) );
        }
        else {
            carp("Cannot find drive hda ID");
            return;
        }
        $hw_id_md5->add("cache-controlEthernet");

        # system bios version string
        my $dmi = Parse::DMIDecode->new();
        $dmi->probe;
        my $bios_version = $dmi->smbios_version();
        $hw_id_md5->add( _info_MD5( $bios_version, 0 ) );

        # CPU name string
        my $info     = Sys::Info->new;
        my $cpu_info = $info->device("CPU");
        my $cpu_name = $cpu_info->identify;
        $hw_id_md5->add( _info_MD5( $cpu_name, 1 ) );

        my $software_registry_file = _get_hive_file();
        my $ProductId;
        my $registry = Parse::Win32Registry->new($software_registry_file);
        my $root_key = $registry->get_root_key;
        my $key_name = 'Microsoft\Windows\CurrentVersion';
        my $key      = $root_key->get_subkey($key_name);
        for my $val ( @{ $key->get_list_of_values } ) {
            $val->as_string =~ /^ProductId.+=\s*(.+)$/;
            if ($1) {
                $ProductId = $1;
                last;
            }
        }
        if ($ProductId) {
            $hw_id_md5->add( _info_MD5( $ProductId, 1 ) );
        }
        else {
            carp("Cannot find the Windows software ProductId from registry");
            return;
        }
        $hardware_string = substr $hw_id_md5->digest, 0, 6;
    }
    $self->{mac} = $hardware_string;

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
    my $sd =
      iTunes::Sid->new( file => 'SCINFOSIDD', key => 'FIND', iv => 'FIND' );
    if ( $sd->sid_version() != 0x10001 ) {
        carp("Incomptible SC Info version");
        return;
    }
    my $mac  = $self->mac();
    my @grup = $sd->FindAtom('grup');
    my $own_grup;
    for my $gp (@grup) {
        my $head = $gp->DirectChildren('head')   or next;
        my $guid = $head->DirectChildren('guid') or next;
        my $guid_mac = substr $guid->NonVersionData(), 0, 6;
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
    my $sb = iTunes::Sid->new( file => 'SCINFOSIDB', key => 'FIND' );
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
            print "Encrypted key $keyID is $encrypted..." if $self->{DEBUG};
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

# Write to .drm directory (do not overwrite unless overwrite is ok )
#   as in $sid->write_keys_to_drms_directory( overwrite_ok => 1 );
sub write_all_user_keys_to_drms_dir {
    my ( $self, %args ) = @_;
    my $overwrite_ok = $args{overwrite_ok};
    my $drm_dir      = _drms_directory();
    mkpath( $drm_dir );
    while ( my ( $userID, $keys ) = each %{ $self->{user_drm_keys} } ) {
        while ( my ( $keyID, $keyval ) = each %{$keys} ) {
            my $filename = sprintf "%s%08X.%03d", $drm_dir, $userID, $keyID;
            next if -f $filename and !$overwrite_ok;
            print "printing key $keyval to file $filename\n" if $self->{DEBUG};
            open my $outf, '>', $filename or do {
                carp(" Cannot open $filename for output: $!");
                next;
            };
            print $outf $keyval;
            close $outf;
        }
    }
}

=head1 B <NAME>

  iTunes::Sid - Apple iTunes SC Info common user database file interface

=head1 B <SYNOPSIS>

=over 4

=back

=head1 B <DESCRIPTION>

=over 4

  This module allows reading and writing of Apple iTunes type 
  I<SC info.sid> databases, including the sidb and sidd files 
  used by iTunes for storage of keys and certificates.

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

=head1 B<SEE ALSO>

=over 4

=item B<Audio::M4P::QuickTime> 

=item B<iTunes::Sid::Atom>

=back

=head1 B<BUGS>

=over 4

Lots.  Windows Vista dual boot compatibility seems flawed.

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

return 1;
