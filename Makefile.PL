use ExtUtils::MakeMaker;

require 5.008;

WriteMakefile(
    NAME         => 'iTunes::Sid',
    AUTHOR       => 'William Hererra (whererra@skylightview.com)',
    ABSTRACT     => 'iTunes SC Info.sidx common user database manipulation',
    VERSION_FROM => 'lib/iTunes/Sid.pm', # finds $VERSION
    LICENSE      => 'Other',
    PREREQ_PM    => { Audio::M4P::Atom => 0.4, Scalar::Util => 0, 
                      Crypt::Rijndael => 0, Digest::MD5 => 0, IPC::Open3 => 0,
                      Crypt::AppleTwoFish => 0.05, File::Basename => 0,
                      Math::BigInt => 0, File::Find::Rule => 0,
                      Carp => 0, List::Util => 0, File::Path => 0,
                    },
);


