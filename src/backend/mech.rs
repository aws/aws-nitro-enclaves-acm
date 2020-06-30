use crate::pkcs11;
use crate::util::{CkRawMechanism, Error as CkRawError};

pub enum Error {
    CkRaw(CkRawError),
    DigestMechMismatch,
    UnknownMech,
}

#[derive(Clone, Copy, Debug)]
pub enum MechDigest {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy, Debug)]
pub enum Mechanism {
    Digest(MechDigest),
    RsaPkcs(Option<MechDigest>),
    RsaPkcsPss(Option<MechDigest>, Option<pkcs11::CK_RSA_PKCS_PSS_PARAMS>),
    RsaX509,
    Ecdsa(Option<MechDigest>),
}

impl Mechanism {
    const RSA_MIN_KEY_BITS: pkcs11::CK_ULONG = 1024;
    const RSA_MAX_KEY_BITS: pkcs11::CK_ULONG = 8192;
    const EC_MIN_KEY_BITS: pkcs11::CK_ULONG = 224;
    const EC_MAX_KEY_BITS: pkcs11::CK_ULONG = 521;

    pub fn from_ckraw_mech(raw_mech: &CkRawMechanism) -> Result<Self, Error> {
        let mech = match raw_mech.type_() {
            pkcs11::CKM_SHA_1 => Self::Digest(MechDigest::Sha1),
            pkcs11::CKM_SHA224 => Self::Digest(MechDigest::Sha224),
            pkcs11::CKM_SHA256 => Self::Digest(MechDigest::Sha256),
            pkcs11::CKM_SHA384 => Self::Digest(MechDigest::Sha384),
            pkcs11::CKM_SHA512 => Self::Digest(MechDigest::Sha512),
            pkcs11::CKM_RSA_PKCS => Self::RsaPkcs(None),
            pkcs11::CKM_SHA1_RSA_PKCS => Self::RsaPkcs(Some(MechDigest::Sha1)),
            pkcs11::CKM_SHA224_RSA_PKCS => Self::RsaPkcs(Some(MechDigest::Sha224)),
            pkcs11::CKM_SHA256_RSA_PKCS => Self::RsaPkcs(Some(MechDigest::Sha256)),
            pkcs11::CKM_SHA384_RSA_PKCS => Self::RsaPkcs(Some(MechDigest::Sha384)),
            pkcs11::CKM_SHA512_RSA_PKCS => Self::RsaPkcs(Some(MechDigest::Sha512)),
            pkcs11::CKM_RSA_PKCS_PSS => Self::RsaPkcsPss(
                None,
                // Safe because Self::RsaPkcsPss defines the correct params struct type
                // (i.e. CK_RSA_PKCS_PSS_PARAMS).
                unsafe { raw_mech.params() }.map_err(Error::CkRaw)?,
            ),
            pkcs11::CKM_SHA1_RSA_PKCS_PSS => Self::RsaPkcsPss(
                Some(MechDigest::Sha1),
                // Safe because Self::RsaPkcsPss defines the correct params struct type
                // (i.e. CK_RSA_PKCS_PSS_PARAMS).
                unsafe { raw_mech.params() }.map_err(Error::CkRaw)?,
            ),
            pkcs11::CKM_SHA224_RSA_PKCS_PSS => Self::RsaPkcsPss(
                Some(MechDigest::Sha224),
                // Safe because Self::RsaPkcsPss defines the correct params struct type
                // (i.e. CK_RSA_PKCS_PSS_PARAMS).
                unsafe { raw_mech.params() }.map_err(Error::CkRaw)?,
            ),
            pkcs11::CKM_SHA256_RSA_PKCS_PSS => Self::RsaPkcsPss(
                Some(MechDigest::Sha256),
                // Safe because Self::RsaPkcsPss defines the correct params struct type
                // (i.e. CK_RSA_PKCS_PSS_PARAMS).
                unsafe { raw_mech.params() }.map_err(Error::CkRaw)?,
            ),
            pkcs11::CKM_SHA384_RSA_PKCS_PSS => Self::RsaPkcsPss(
                Some(MechDigest::Sha384),
                // Safe because Self::RsaPkcsPss defines the correct params struct type
                // (i.e. CK_RSA_PKCS_PSS_PARAMS).
                unsafe { raw_mech.params() }.map_err(Error::CkRaw)?,
            ),
            pkcs11::CKM_SHA512_RSA_PKCS_PSS => Self::RsaPkcsPss(
                Some(MechDigest::Sha512),
                // Safe because Self::RsaPkcsPss defines the correct params struct type
                // (i.e. CK_RSA_PKCS_PSS_PARAMS).
                unsafe { raw_mech.params() }.map_err(Error::CkRaw)?,
            ),
            pkcs11::CKM_RSA_X_509 => Self::RsaX509,
            pkcs11::CKM_ECDSA => Self::Ecdsa(None),
            pkcs11::CKM_ECDSA_SHA1 => Self::Ecdsa(Some(MechDigest::Sha1)),
            pkcs11::CKM_ECDSA_SHA224 => Self::Ecdsa(Some(MechDigest::Sha224)),
            pkcs11::CKM_ECDSA_SHA256 => Self::Ecdsa(Some(MechDigest::Sha256)),
            pkcs11::CKM_ECDSA_SHA384 => Self::Ecdsa(Some(MechDigest::Sha384)),
            pkcs11::CKM_ECDSA_SHA512 => Self::Ecdsa(Some(MechDigest::Sha512)),

            _ => return Err(Error::UnknownMech),
        };

        // Sanity check: the mechanism-defined hash algorithm must match the algorithm defined
        // by its parameters (if any).
        if let Self::RsaPkcsPss(Some(digest), Some(params)) = mech {
            if params.hashAlg != Self::Digest(digest).ck_type() {
                return Err(Error::DigestMechMismatch);
            }
        }

        Ok(mech)
    }

    pub fn ck_type(&self) -> pkcs11::CK_MECHANISM_TYPE {
        match self {
            Self::Digest(digest) => match digest {
                MechDigest::Sha1 => pkcs11::CKM_SHA_1,
                MechDigest::Sha224 => pkcs11::CKM_SHA224,
                MechDigest::Sha256 => pkcs11::CKM_SHA256,
                MechDigest::Sha384 => pkcs11::CKM_SHA384,
                MechDigest::Sha512 => pkcs11::CKM_SHA512,
            },
            Self::RsaPkcs(digest) => match digest {
                None => pkcs11::CKM_RSA_PKCS,
                Some(MechDigest::Sha1) => pkcs11::CKM_SHA1_RSA_PKCS,
                Some(MechDigest::Sha224) => pkcs11::CKM_SHA224_RSA_PKCS,
                Some(MechDigest::Sha256) => pkcs11::CKM_SHA256_RSA_PKCS,
                Some(MechDigest::Sha384) => pkcs11::CKM_SHA384_RSA_PKCS,
                Some(MechDigest::Sha512) => pkcs11::CKM_SHA512_RSA_PKCS,
            },
            Self::RsaPkcsPss(digest, _) => match digest {
                None => pkcs11::CKM_RSA_PKCS_PSS,
                Some(MechDigest::Sha1) => pkcs11::CKM_SHA1_RSA_PKCS_PSS,
                Some(MechDigest::Sha224) => pkcs11::CKM_SHA224_RSA_PKCS_PSS,
                Some(MechDigest::Sha256) => pkcs11::CKM_SHA256_RSA_PKCS_PSS,
                Some(MechDigest::Sha384) => pkcs11::CKM_SHA384_RSA_PKCS_PSS,
                Some(MechDigest::Sha512) => pkcs11::CKM_SHA512_RSA_PKCS_PSS,
            },
            Self::RsaX509 => pkcs11::CKM_RSA_X_509,
            Self::Ecdsa(digest) => match digest {
                None => pkcs11::CKM_ECDSA,
                Some(MechDigest::Sha1) => pkcs11::CKM_ECDSA_SHA1,
                Some(MechDigest::Sha224) => pkcs11::CKM_ECDSA_SHA224,
                Some(MechDigest::Sha256) => pkcs11::CKM_ECDSA_SHA256,
                Some(MechDigest::Sha384) => pkcs11::CKM_ECDSA_SHA384,
                Some(MechDigest::Sha512) => pkcs11::CKM_ECDSA_SHA512,
            },
        }
    }

    pub fn ck_info(&self) -> pkcs11::CK_MECHANISM_INFO {
        let (min_bits, max_bits) = match self {
            Self::Digest(_) => (0, 0),
            Self::RsaPkcs(_) | Self::RsaPkcsPss(_, _) | Self::RsaX509 => {
                (Self::RSA_MIN_KEY_BITS, Self::RSA_MAX_KEY_BITS)
            }
            Self::Ecdsa(_) => (Self::EC_MIN_KEY_BITS, Self::EC_MAX_KEY_BITS),
        };
        pkcs11::CK_MECHANISM_INFO {
            ulMinKeySize: min_bits,
            ulMaxKeySize: max_bits,
            flags: self.ck_flags(),
        }
    }

    pub fn ck_flags(&self) -> pkcs11::CK_FLAGS {
        // NOTE: Though we have a soft-token, we stamp the pkcs11::CKF_HW flag since most unit
        // tests out there seem to check for it
        pkcs11::CKF_HW
            | match self {
                Self::Digest(_) => pkcs11::CKF_DIGEST,
                // Single-part CKM_RSA_PKCS also has encrypt/decrypt
                Self::RsaPkcs(None) => {
                    pkcs11::CKF_SIGN
                        | pkcs11::CKF_VERIFY
                        | pkcs11::CKF_DECRYPT
                        | pkcs11::CKF_ENCRYPT
                }
                // Multi-part CKM_RSA_PKCS has sign/verify only
                Self::RsaPkcs(Some(_)) => pkcs11::CKF_SIGN | pkcs11::CKF_VERIFY,
                Self::RsaPkcsPss(_, _) => pkcs11::CKF_SIGN | pkcs11::CKF_VERIFY,
                Self::RsaX509 => {
                    pkcs11::CKF_SIGN
                        | pkcs11::CKF_VERIFY
                        | pkcs11::CKF_DECRYPT
                        | pkcs11::CKF_ENCRYPT
                }
                Self::Ecdsa(_) => {
                    pkcs11::CKF_SIGN
                        | pkcs11::CKF_VERIFY
                        | pkcs11::CKF_EC_F_P
                        | pkcs11::CKF_EC_NAMEDCURVE
                        | pkcs11::CKF_EC_UNCOMPRESS
                }
            }
    }

    pub fn is_multipart(&self) -> bool {
        match self {
            Self::RsaPkcs(ref digest)
            | Self::RsaPkcsPss(ref digest, _)
            | Self::Ecdsa(ref digest) => digest.is_some(),
            _ => false,
        }
    }
}
