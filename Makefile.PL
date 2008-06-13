use ExtUtils::MakeMaker;

require 5.008;

WriteMakefile(
    NAME         => 'iTunes::Sid',
    AUTHOR       => 'William Hererra (whererra@skylightview.com)',
    ABSTRACT     => 'Perl iTunes compatible common user database manipulation',
    VERSION_FROM => 'lib/iTunes/Sid.pm', # finds $VERSION
    LICENSE      => 'Other',
    PREREQ_PM    => { Audio::M4P::Atom => 0.4, Scalar::Util => 0, 
                      Crypt::Rijndael => 0, Digest::MD5 => 0,
                      Crypt::AppleTwoFish => 0.5, Win32::Registry::File => 0,
                      Math::BigInt => 0,
                    },
);


