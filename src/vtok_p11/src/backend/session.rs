use std::cmp;

use super::db::{Db, Object, ObjectHandle, ObjectKind};
use super::Mechanism;
use crate::crypto;
use crate::crypto::{
    DecryptCtx, DigestCtx, DigestSignCtx, DigestVerifyCtx, DirectDecryptCtx, DirectEncryptCtx,
    DirectSignCtx, DirectVerifyCtx, EncryptCtx, SignCtx, VerifyCtx,
};
use crate::pkcs11;
use crate::util::CkRawAttrTemplate;
use crate::{Error, Result};

struct EnumCtx {
    handles: Vec<ObjectHandle>,
    index: usize,
}

impl EnumCtx {
    fn new(handles: Vec<ObjectHandle>) -> Self {
        Self { handles, index: 0 }
    }
    fn next_chunk(&mut self, count: usize) -> &[ObjectHandle] {
        let end = cmp::min(self.index + count, self.handles.len());
        let ret = &self.handles[self.index..end];
        self.index += ret.len();
        ret
    }
}

#[derive(Clone, Copy)]
pub enum SessionState {
    RoPublic,
    RoUser,
}

/// The active session states
/// New sessions start with R/O Public state and once
/// the user logins, the session shall enter R/O User Functions
/// state. Logout will cause the state to transition back to
/// the R/O Public state.
impl SessionState {
    fn to_ck_state(&self) -> pkcs11::CK_STATE {
        match self {
            Self::RoPublic => pkcs11::CKS_RO_PUBLIC_SESSION,
            Self::RoUser => pkcs11::CKS_RO_USER_FUNCTIONS,
        }
    }
}

/// The session container. Holds the provisioned object database
/// and also the operation context currently active (if any).
/// The enumeration context is used only when user requests to
/// find all objects attached. The other contexts are during actual
/// session cryptopgrahic operations. Due to the nature of the Cryptoki
/// PKCS#11 specification all operation contexts (digest, sign, verify,
/// encrypt, decrypt) are mutually exclusive.
pub struct Session {
    slot_id: pkcs11::CK_SLOT_ID,
    state: SessionState,
    db: Db,
    enum_ctx: Option<EnumCtx>,
    digest_ctx: Option<DigestCtx>,
    sign_ctx: Option<Box<dyn SignCtx>>,
    verify_ctx: Option<Box<dyn VerifyCtx>>,
    decrypt_ctx: Option<Box<dyn DecryptCtx>>,
    encrypt_ctx: Option<Box<dyn EncryptCtx>>,
}

impl Session {
    pub fn new(slot_id: pkcs11::CK_SLOT_ID, db: Db, state: SessionState) -> Self {
        Self {
            slot_id,
            state,
            db,
            enum_ctx: None,
            digest_ctx: None,
            sign_ctx: None,
            verify_ctx: None,
            decrypt_ctx: None,
            encrypt_ctx: None,
        }
    }

    pub fn ck_info(&self) -> pkcs11::CK_SESSION_INFO {
        pkcs11::CK_SESSION_INFO {
            slotID: self.slot_id,
            state: self.state.to_ck_state(),
            flags: pkcs11::CKF_SERIAL_SESSION,
            ulDeviceError: pkcs11::CKR_OK,
        }
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn set_state(&mut self, state: SessionState) {
        self.state = state
    }

    pub fn object(&self, handle: ObjectHandle) -> Option<&Object> {
        self.db.object(handle)
    }

    /// Enumerate session objects, possibly matching a given template.
    /// If no template is provided, all available objects are enumerated.
    pub fn enum_init(&mut self, template: Option<CkRawAttrTemplate>) {
        let enable_private = self.check_user_logged_in().is_ok();
        let handles: Vec<ObjectHandle> = self
            .db
            .enumerate()
            .filter_map(|(h, o)| {
                let pass = (enable_private || !o.is_private())
                    && template
                        .as_ref()
                        .map(|tpl| o.match_attr_template(tpl))
                        // Per the PKCS#11 2.40 spec, mechanism objects should not be listed
                        // unless specifically searched for by using a template with
                        // CKA_CLASS = CKO_MECHANISM.
                        .unwrap_or(!o.is_mechanism());
                if pass {
                    Some(h)
                } else {
                    None
                }
            })
            .collect();
        self.enum_ctx = Some(EnumCtx::new(handles));
    }

    pub fn enum_next_chunk(&mut self, count: usize) -> Option<&[ObjectHandle]> {
        self.enum_ctx.as_mut().map(|x| x.next_chunk(count))
    }

    /// Enumeration is already in progress
    pub fn enum_active(&self) -> bool {
        self.enum_ctx.is_some()
    }

    /// Finalize an active enumeration operation
    pub fn enum_finalize(&mut self) -> Result<()> {
        self.enum_ctx
            .take()
            .ok_or(Error::CkError(pkcs11::CKR_OPERATION_NOT_INITIALIZED))?;
        Ok(())
    }

    /// Initialize a digest context for a digest operation
    pub fn digest_init(&mut self, mech_type: pkcs11::CK_MECHANISM_TYPE) -> Result<()> {
        self.digest_ctx = Some(
            DigestCtx::new(mech_type).map_err(|_| Error::CkError(pkcs11::CKR_MECHANISM_INVALID))?,
        );
        Ok(())
    }

    pub fn digest_ctx(&mut self) -> &mut Option<crypto::DigestCtx> {
        &mut self.digest_ctx
    }

    /// Initialize a signing context for a signing operation
    pub fn sign_init(&mut self, mech: &Mechanism, key_handle: ObjectHandle) -> Result<()> {
        self.check_user_logged_in()?;
        let pkey = self.private_key_for_mech(mech, key_handle)?;
        self.sign_ctx = Some(if mech.is_multipart() {
            Box::new(DigestSignCtx::new(mech, pkey).map_err(Error::CryptoError)?)
        } else {
            Box::new(DirectSignCtx::new(mech, pkey).map_err(Error::CryptoError)?)
        });
        Ok(())
    }

    pub fn sign_ctx(&mut self) -> &mut Option<Box<dyn SignCtx>> {
        &mut self.sign_ctx
    }

    /// Initialize a verification context for a verification operation
    pub fn verify_init(&mut self, mech: &Mechanism, key_handle: ObjectHandle) -> Result<()> {
        self.check_user_logged_in()?;
        let pkey = self.public_key_for_mech(mech, key_handle)?;
        self.verify_ctx = Some(if mech.is_multipart() {
            Box::new(DigestVerifyCtx::new(mech, pkey).map_err(Error::CryptoError)?)
        } else {
            Box::new(DirectVerifyCtx::new(mech, pkey).map_err(Error::CryptoError)?)
        });
        Ok(())
    }

    pub fn verify_ctx(&mut self) -> &mut Option<Box<dyn VerifyCtx>> {
        &mut self.verify_ctx
    }

    /// Initialize an encryption context for an encryption operation
    pub fn encrypt_init(&mut self, mech: &Mechanism, key_handle: ObjectHandle) -> Result<()> {
        self.check_user_logged_in()?;
        let pkey = self.public_key_for_mech(mech, key_handle)?;
        self.encrypt_ctx = Some(if mech.is_multipart() {
            return Err(Error::MechanismInvalid);
        } else {
            Box::new(DirectEncryptCtx::new(mech, pkey).map_err(Error::CryptoError)?)
        });
        Ok(())
    }

    pub fn encrypt_ctx(&mut self) -> &mut Option<Box<dyn EncryptCtx>> {
        &mut self.encrypt_ctx
    }

    /// Initialize an decryption context for a decryption operation
    pub fn decrypt_init(&mut self, mech: &Mechanism, key_handle: ObjectHandle) -> Result<()> {
        self.check_user_logged_in()?;
        let pkey = self.private_key_for_mech(mech, key_handle)?;
        self.decrypt_ctx = Some(if mech.is_multipart() {
            return Err(Error::MechanismInvalid);
        } else {
            Box::new(DirectDecryptCtx::new(mech, pkey).map_err(Error::CryptoError)?)
        });
        Ok(())
    }

    pub fn decrypt_ctx(&mut self) -> &mut Option<Box<dyn DecryptCtx>> {
        &mut self.decrypt_ctx
    }

    /// Helper for checking if the user has been logged in. Some cryptograhic
    /// operations (i.e. signing with private keys) require login.
    fn check_user_logged_in(&self) -> Result<()> {
        match self.state {
            SessionState::RoUser => Ok(()),
            _ => Err(Error::UserNotLoggedIn),
        }
    }

    /// Constructs an EVP_PKEY wrapper object from a p11 object based on an input
    /// PEM formatted string while also keeping consistency with the requested mechanism.
    fn private_key_for_mech(
        &self,
        mech: &Mechanism,
        key_handle: ObjectHandle,
    ) -> Result<crypto::Pkey> {
        let key_obj = self.db.object(key_handle).ok_or(Error::KeyHandleInvalid)?;
        match mech {
            Mechanism::RsaX509 | Mechanism::RsaPkcs(..) | Mechanism::RsaPkcsPss(..) => {
                if let ObjectKind::RsaPrivateKey(pem) = key_obj.kind() {
                    crypto::Pkey::from_private_pem(pem.as_str()).map_err(Error::CryptoError)
                } else {
                    Err(Error::KeyTypeInconsistent)
                }
            }
            Mechanism::Ecdsa(..) => {
                if let ObjectKind::EcPrivateKey(pem) = key_obj.kind() {
                    crypto::Pkey::from_private_pem(pem.as_str()).map_err(Error::CryptoError)
                } else {
                    Err(Error::KeyTypeInconsistent)
                }
            }
            _ => Err(Error::MechanismInvalid),
        }
    }

    /// Constructs an internal public key object type from the provisioned PEM file
    fn public_key_for_mech(
        &self,
        mech: &Mechanism,
        key_handle: ObjectHandle,
    ) -> Result<crypto::Pkey> {
        let key_obj = self.db.object(key_handle).ok_or(Error::KeyHandleInvalid)?;
        match mech {
            Mechanism::RsaX509 | Mechanism::RsaPkcs(..) | Mechanism::RsaPkcsPss(..) => {
                if let ObjectKind::RsaPublicKey(pem) = key_obj.kind() {
                    crypto::Pkey::from_private_pem(pem.as_str()).map_err(Error::CryptoError)
                } else {
                    Err(Error::KeyTypeInconsistent)
                }
            }
            Mechanism::Ecdsa(..) => {
                if let ObjectKind::EcPublicKey(pem) = key_obj.kind() {
                    crypto::Pkey::from_private_pem(pem.as_str()).map_err(Error::CryptoError)
                } else {
                    Err(Error::KeyTypeInconsistent)
                }
            }
            _ => Err(Error::MechanismInvalid),
        }
    }
}
