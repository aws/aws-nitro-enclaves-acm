extern crate lazy_static;
#[macro_use]
extern crate log;

#[macro_use]
mod util;
mod api;
mod backend;
mod crypto;
mod pkcs11;

use crate::crypto::Error as CryptoError;
use backend::token::Error as TokenError;

/// Device, slot and token capabilities and information
mod defs {
    use super::backend::mech::{MechDigest, Mechanism};
    use super::pkcs11;

    pub const CRYPTOKI_VERSION: pkcs11::CK_VERSION = ck_version!(
        pkcs11::CRYPTOKI_VERSION_MAJOR as u8,
        pkcs11::CRYPTOKI_VERSION_MINOR as u8
    );

    pub const DEVICE_DESCRIPTION: &str = "EncryptionVault";
    pub const DEVICE_VERSION: pkcs11::CK_VERSION = ck_version!(0, 1);
    pub const DEVICE_MANUFACTURER: &str = "Amazon";

    pub const SLOT_DESCRIPTION: &str = "EncryptionVault-Slot";
    pub const SLOT_HARDWARE_VERSION: pkcs11::CK_VERSION = ck_version!(0, 1);
    pub const SLOT_FIRMWARE_VERSION: pkcs11::CK_VERSION = ck_version!(0, 1);
    pub const SLOT_MANUFACTURER: &str = "Amazon";
    pub const MAX_SLOTS: usize = 4;

    pub const TOKEN_LABEL: &str = "EncryptionVault-Token";
    pub const TOKEN_MANUFACTURER: &str = "Amazon";
    pub const TOKEN_MODEL: &str = "Nitro-vToken";
    pub const TOKEN_MAX_SESSIONS: pkcs11::CK_ULONG = 1024;
    pub const TOKEN_MAX_RW_SESSIONS: pkcs11::CK_ULONG = 0;
    pub const TOKEN_MAX_PIN_LEN: pkcs11::CK_ULONG = 64;
    pub const TOKEN_MIN_PIN_LEN: pkcs11::CK_ULONG = 4;
    pub const TOKEN_HARDWARE_VERSION: pkcs11::CK_VERSION = ck_version!(0, 1);
    pub const TOKEN_FIRMWARE_VERSION: pkcs11::CK_VERSION = ck_version!(0, 1);
    pub const TOKEN_UTC_TIME: &str = "";

    pub const TOKEN_MECH_LIST: [Mechanism; 24] = [
        Mechanism::Digest(MechDigest::Sha1),
        Mechanism::Digest(MechDigest::Sha224),
        Mechanism::Digest(MechDigest::Sha256),
        Mechanism::Digest(MechDigest::Sha384),
        Mechanism::Digest(MechDigest::Sha512),
        Mechanism::RsaPkcs(None),
        Mechanism::RsaPkcs(Some(MechDigest::Sha1)),
        Mechanism::RsaPkcs(Some(MechDigest::Sha224)),
        Mechanism::RsaPkcs(Some(MechDigest::Sha256)),
        Mechanism::RsaPkcs(Some(MechDigest::Sha384)),
        Mechanism::RsaPkcs(Some(MechDigest::Sha512)),
        Mechanism::RsaPkcsPss(None, None),
        Mechanism::RsaPkcsPss(Some(MechDigest::Sha1), None),
        Mechanism::RsaPkcsPss(Some(MechDigest::Sha224), None),
        Mechanism::RsaPkcsPss(Some(MechDigest::Sha256), None),
        Mechanism::RsaPkcsPss(Some(MechDigest::Sha384), None),
        Mechanism::RsaPkcsPss(Some(MechDigest::Sha512), None),
        Mechanism::RsaX509,
        Mechanism::Ecdsa(None),
        Mechanism::Ecdsa(Some(MechDigest::Sha1)),
        Mechanism::Ecdsa(Some(MechDigest::Sha224)),
        Mechanism::Ecdsa(Some(MechDigest::Sha256)),
        Mechanism::Ecdsa(Some(MechDigest::Sha384)),
        Mechanism::Ecdsa(Some(MechDigest::Sha512)),
    ];
}

/// Helper for comparing Criptoki versions
impl PartialEq for pkcs11::CK_VERSION {
    fn eq(&self, other: &Self) -> bool {
        self.major == other.major && self.minor == other.minor
    }
}

mod data {
    use lazy_static::lazy_static;
    use std::sync::{Arc, Mutex};

    use super::api;
    use super::api::nyi;
    use super::backend::device::Device;
    use super::defs;
    use super::pkcs11::*;

    /// Supported Criptoki PKCS#11 functions. As per specification,
    /// all functions are exported but some return CKR_FUNCTION_NOT_SUPPORTED.
    pub static FN_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
        version: defs::DEVICE_VERSION,
        C_Initialize: Some(api::C_Initialize),
        C_Finalize: Some(api::C_Finalize),
        C_GetInfo: Some(api::C_GetInfo),
        C_GetFunctionList: Some(api::C_GetFunctionList),
        C_GetSlotList: Some(api::token::C_GetSlotList),
        C_GetSlotInfo: Some(api::token::C_GetSlotInfo),
        C_GetTokenInfo: Some(api::token::C_GetTokenInfo),
        C_GetMechanismList: Some(api::token::C_GetMechanismList),
        C_GetMechanismInfo: Some(api::token::C_GetMechanismInfo),
        C_InitToken: Some(api::token::C_InitToken),
        C_InitPIN: Some(nyi::C_InitPIN),
        C_SetPIN: Some(nyi::C_SetPIN),
        C_OpenSession: Some(api::session::C_OpenSession),
        C_CloseSession: Some(api::session::C_CloseSession),
        C_CloseAllSessions: Some(api::session::C_CloseAllSessions),
        C_GetSessionInfo: Some(api::session::C_GetSessionInfo),
        C_GetOperationState: Some(nyi::C_GetOperationState),
        C_SetOperationState: Some(nyi::C_SetOperationState),
        C_Login: Some(api::token::C_Login),
        C_Logout: Some(api::token::C_Logout),
        C_CreateObject: Some(nyi::C_CreateObject),
        C_CopyObject: Some(nyi::C_CopyObject),
        C_DestroyObject: Some(nyi::C_DestroyObject),
        C_GetObjectSize: Some(api::object::C_GetObjectSize),
        C_GetAttributeValue: Some(api::object::C_GetAttributeValue),
        C_SetAttributeValue: Some(nyi::C_SetAttributeValue),
        C_FindObjectsInit: Some(api::object::C_FindObjectsInit),
        C_FindObjects: Some(api::object::C_FindObjects),
        C_FindObjectsFinal: Some(api::object::C_FindObjectsFinal),
        C_EncryptInit: Some(api::encrypt::C_EncryptInit),
        C_Encrypt: Some(api::encrypt::C_Encrypt),
        C_EncryptUpdate: Some(nyi::C_EncryptUpdate),
        C_EncryptFinal: Some(nyi::C_EncryptFinal),
        C_DecryptInit: Some(api::decrypt::C_DecryptInit),
        C_Decrypt: Some(api::decrypt::C_Decrypt),
        C_DecryptUpdate: Some(nyi::C_DecryptUpdate),
        C_DecryptFinal: Some(nyi::C_DecryptFinal),
        C_DigestInit: Some(api::digest::C_DigestInit),
        C_Digest: Some(api::digest::C_Digest),
        C_DigestUpdate: Some(api::digest::C_DigestUpdate),
        C_DigestKey: Some(nyi::C_DigestKey),
        C_DigestFinal: Some(api::digest::C_DigestFinal),
        C_SignInit: Some(api::sign::C_SignInit),
        C_Sign: Some(api::sign::C_Sign),
        C_SignUpdate: Some(api::sign::C_SignUpdate),
        C_SignFinal: Some(api::sign::C_SignFinal),
        C_SignRecoverInit: Some(nyi::C_SignRecoverInit),
        C_SignRecover: Some(nyi::C_SignRecover),
        C_VerifyInit: Some(api::verify::C_VerifyInit),
        C_Verify: Some(api::verify::C_Verify),
        C_VerifyUpdate: Some(api::verify::C_VerifyUpdate),
        C_VerifyFinal: Some(api::verify::C_VerifyFinal),
        C_VerifyRecoverInit: Some(nyi::C_VerifyRecoverInit),
        C_VerifyRecover: Some(nyi::C_VerifyRecover),
        C_DigestEncryptUpdate: Some(nyi::C_DigestEncryptUpdate),
        C_DecryptDigestUpdate: Some(nyi::C_DecryptDigestUpdate),
        C_SignEncryptUpdate: Some(nyi::C_SignEncryptUpdate),
        C_DecryptVerifyUpdate: Some(nyi::C_DecryptVerifyUpdate),
        C_GenerateKey: Some(nyi::C_GenerateKey),
        C_GenerateKeyPair: Some(nyi::C_GenerateKeyPair),
        C_WrapKey: Some(nyi::C_WrapKey),
        C_UnwrapKey: Some(nyi::C_UnwrapKey),
        C_DeriveKey: Some(nyi::C_DeriveKey),
        C_SeedRandom: Some(nyi::C_SeedRandom),
        C_GenerateRandom: Some(nyi::C_GenerateRandom),
        C_GetFunctionStatus: Some(api::session::C_GetFunctionStatus),
        C_CancelFunction: Some(api::session::C_CancelFunction),
        C_WaitForSlotEvent: Some(nyi::C_WaitForSlotEvent),
    };

    lazy_static! {
        pub static ref DEVICE: Arc<Mutex<Option<Device>>> = Arc::new(Mutex::new(None));
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Error {
    CkError(pkcs11::CK_RV),
    CryptoError(crypto::Error),
    KeyHandleInvalid,
    KeyTypeInconsistent,
    MechanismInvalid,
    OperationNotInitialized,
    SessionHandleInvalid,
    SessionLockPoisoned,
    SlotIdInvalid,
    UserNotLoggedIn,
    TokenError(TokenError),
    TokenNotPresent,
    TokenUninit,
    // TODO: implement proper error reporting
    GeneralError,
}

impl Error {
    pub fn ck_rv(&self) -> pkcs11::CK_RV {
        match self {
            Self::CkError(code) => *code,
            Self::CryptoError(CryptoError::DataMissing) => pkcs11::CKR_DATA_LEN_RANGE,
            Self::CryptoError(CryptoError::OperationActive) => pkcs11::CKR_OPERATION_ACTIVE,
            Self::CryptoError(CryptoError::DigestVerifyFinal) => pkcs11::CKR_SIGNATURE_INVALID,
            Self::CryptoError(CryptoError::DigestVerify) => pkcs11::CKR_SIGNATURE_INVALID,
            Self::CryptoError(CryptoError::DirectVerify) => pkcs11::CKR_SIGNATURE_INVALID,
            Self::KeyHandleInvalid => pkcs11::CKR_KEY_HANDLE_INVALID,
            Self::KeyTypeInconsistent => pkcs11::CKR_KEY_TYPE_INCONSISTENT,
            Self::MechanismInvalid => pkcs11::CKR_MECHANISM_INVALID,
            Self::OperationNotInitialized => pkcs11::CKR_OPERATION_NOT_INITIALIZED,
            Self::SessionHandleInvalid => pkcs11::CKR_SESSION_HANDLE_INVALID,
            Self::SlotIdInvalid => pkcs11::CKR_SLOT_ID_INVALID,
            Self::UserNotLoggedIn => pkcs11::CKR_USER_NOT_LOGGED_IN,
            Self::TokenNotPresent => pkcs11::CKR_TOKEN_NOT_PRESENT,
            Self::TokenError(TokenError::SessionCount) => pkcs11::CKR_SESSION_COUNT,
            Self::TokenError(TokenError::SessionHandleInvalid) => {
                pkcs11::CKR_SESSION_HANDLE_INVALID
            }
            Self::TokenError(TokenError::UserAlreadyLoggedIn) => pkcs11::CKR_USER_ALREADY_LOGGED_IN,
            Self::TokenError(TokenError::UserNotLoggedIn) => pkcs11::CKR_USER_NOT_LOGGED_IN,
            Self::TokenError(TokenError::MechNotFound) => pkcs11::CKR_MECHANISM_INVALID,
            Self::TokenError(TokenError::PinIncorrect) => pkcs11::CKR_PIN_INCORRECT,
            _ => pkcs11::CKR_GENERAL_ERROR,
        }
    }
}

impl From<Error> for pkcs11::CK_RV {
    fn from(src: Error) -> pkcs11::CK_RV {
        src.ck_rv()
    }
}

pub type Result<T> = std::result::Result<T, Error>;
