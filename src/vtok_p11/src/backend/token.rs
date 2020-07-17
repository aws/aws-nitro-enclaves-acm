use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::defs;
use crate::pkcs11;

use super::db;
use super::db::{Db, ObjectKind};
use super::session::{Session, SessionState};
use super::Mechanism;

#[derive(Clone, Copy, Debug)]
pub enum Error {
    DbLoad(db::Error),
    MechNotFound,
    PinIncorrect,
    SessionCount,
    SessionHandleInvalid,
    SessionLockPoisoned,
    UserAlreadyLoggedIn,
    UserNotLoggedIn,
    TokenUninit,
}
pub type Result<T> = std::result::Result<T, Error>;

/// Slot token container. Contains all active sessions created against
/// the parent slot of this token. The database is attached to the token
/// and each session receives a copy of the provisioned database for
/// working with the database objects. The user must login successfuly
/// in order to actually do cryptographic operations in the context of
/// that respective session.
pub struct Token {
    slot_id: pkcs11::CK_SLOT_ID,
    sessions: HashMap<pkcs11::CK_SESSION_HANDLE, Arc<Mutex<Session>>>,
    db: Option<Db>,
    user_login: bool,
}

impl Token {
    pub fn new(slot_id: pkcs11::CK_SLOT_ID) -> Self {
        Self {
            slot_id,
            sessions: HashMap::new(),
            //db: None,
            // TODO: implement proper init and remove this hardcoding
            db: Some(Db::from_test_data().unwrap()),
            user_login: false,
        }
    }

    pub fn init(&mut self, _pin: &str) -> Result<()> {
        // TODO: implement proper DB loading
        self.db = Some(Db::from_test_data().map_err(Error::DbLoad)?);
        Ok(())
    }

    pub fn ck_info(&self) -> pkcs11::CK_TOKEN_INFO {
        let mut flags = match self.db.as_ref() {
            Some(db) => {
                // If provisioning was successful, then it means
                // the user initialized the token along with a CK_USER PIN
                pkcs11::CKF_TOKEN_INITIALIZED
                    | pkcs11::CKF_USER_PIN_INITIALIZED
                    | if db.enumerate().any(|(_, o)| o.is_private()) {
                        // If any private objects are present then
                        // the user must login before being able to
                        // do certain operations (i.e. signing).
                        pkcs11::CKF_LOGIN_REQUIRED
                    } else {
                        0
                    }
            }
            None => 0,
        };

        // Persistent token flags: only CK_USER R/O are sessions supported
        flags |= pkcs11::CKF_WRITE_PROTECTED | pkcs11::CKF_SO_PIN_LOCKED;

        // TODO: set serial properly
        let serial = format!("EVT{:02}", self.slot_id);

        pkcs11::CK_TOKEN_INFO {
            label: ck_padded_str!(defs::TOKEN_LABEL, 32),
            manufacturerID: ck_padded_str!(defs::TOKEN_MANUFACTURER, 32),
            model: ck_padded_str!(defs::TOKEN_MODEL, 16),
            serialNumber: ck_padded_str!(serial.as_str(), 16),
            flags,
            ulMaxSessionCount: defs::TOKEN_MAX_SESSIONS,
            ulSessionCount: self.sessions.len() as pkcs11::CK_ULONG,
            ulMaxRwSessionCount: defs::TOKEN_MAX_RW_SESSIONS,
            ulRwSessionCount: 0,
            ulMaxPinLen: defs::TOKEN_MAX_PIN_LEN,
            ulMinPinLen: defs::TOKEN_MIN_PIN_LEN,
            ulTotalPublicMemory: pkcs11::CK_UNAVAILABLE_INFORMATION,
            ulFreePublicMemory: pkcs11::CK_UNAVAILABLE_INFORMATION,
            ulTotalPrivateMemory: pkcs11::CK_UNAVAILABLE_INFORMATION,
            ulFreePrivateMemory: pkcs11::CK_UNAVAILABLE_INFORMATION,
            hardwareVersion: defs::TOKEN_HARDWARE_VERSION,
            firmwareVersion: defs::TOKEN_FIRMWARE_VERSION,
            utcTime: ck_padded_str!(defs::TOKEN_UTC_TIME, 16),
        }
    }

    pub fn open_session(&mut self, handle: pkcs11::CK_SESSION_HANDLE) -> Result<()> {
        if self.sessions.len() >= defs::TOKEN_MAX_SESSIONS as usize {
            return Err(Error::SessionCount);
        }
        let db_clone = self.db.as_ref().cloned().ok_or(Error::TokenUninit)?;
        let state = match self.user_login {
            // If an active user login is present on the token, all future
            // sessions from the user shall enter RoUser state implicitly
            true => SessionState::RoUser,
            false => SessionState::RoPublic,
        };
        self.sessions.insert(
            handle,
            Arc::new(Mutex::new(Session::new(self.slot_id, db_clone, state))),
        );

        Ok(())
    }

    pub fn close_session(&mut self, handle: pkcs11::CK_SESSION_HANDLE) -> Result<()> {
        self.sessions
            .remove(&handle)
            .ok_or(Error::SessionHandleInvalid)
            .map(|_| ())
    }

    pub fn close_all_sessions(&mut self) {
        self.sessions.clear();
    }

    pub fn session(&self, handle: pkcs11::CK_SESSION_HANDLE) -> Option<Arc<Mutex<Session>>> {
        self.sessions.get(&handle).cloned()
    }

    pub fn login(&mut self, session_handle: pkcs11::CK_SESSION_HANDLE, pin: &str) -> Result<()> {
        if self.db.as_ref().ok_or(Error::TokenUninit)?.token_pin() != pin {
            return Err(Error::PinIncorrect);
        }
        let sarc = self
            .session(session_handle)
            .ok_or(Error::SessionHandleInvalid)?;
        let mut session = sarc.lock().map_err(|_| Error::SessionLockPoisoned)?;
        match session.state() {
            SessionState::RoUser => return Err(Error::UserAlreadyLoggedIn),
            SessionState::RoPublic => session.set_state(SessionState::RoUser),
        };

        for (handle, sarc) in self.sessions.iter() {
            if *handle != session_handle {
                sarc.lock()
                    .map_err(|_| Error::SessionLockPoisoned)?
                    .set_state(SessionState::RoUser);
            }
        }

        // Token now has an active user login
        self.user_login = true;

        Ok(())
    }

    pub fn logout(&mut self, session_handle: pkcs11::CK_SESSION_HANDLE) -> Result<()> {
        let sarc = self
            .session(session_handle)
            .ok_or(Error::SessionHandleInvalid)?;
        let mut session = sarc.lock().map_err(|_| Error::SessionLockPoisoned)?;
        match session.state() {
            SessionState::RoPublic => return Err(Error::UserNotLoggedIn),
            SessionState::RoUser => session.set_state(SessionState::RoPublic),
        };
        for (handle, sarc) in self.sessions.iter() {
            if *handle != session_handle {
                sarc.lock()
                    .map_err(|_| Error::SessionLockPoisoned)?
                    .set_state(SessionState::RoPublic);
            }
        }

        // Token now has an inactive user login
        self.user_login = false;

        Ok(())
    }

    pub fn mech_count(&self) -> Result<usize> {
        Ok(self
            .db
            .as_ref()
            .ok_or(Error::TokenUninit)?
            .enumerate()
            .filter_map(|(_, obj)| match obj.kind() {
                ObjectKind::Mechanism(_) => Some(true),
                _ => None,
            })
            .count())
    }

    pub fn mech_list(&self) -> Result<Vec<Mechanism>> {
        Ok(self
            .db
            .as_ref()
            .ok_or(Error::TokenUninit)?
            .enumerate()
            .filter_map(|(_, obj)| match obj.kind() {
                ObjectKind::Mechanism(mech) => Some(*mech),
                _ => None,
            })
            .collect())
    }

    pub fn mech(&self, mech_type: pkcs11::CK_MECHANISM_TYPE) -> Result<Mechanism> {
        self.db
            .as_ref()
            .ok_or(Error::TokenUninit)?
            .enumerate()
            .filter_map(|(_, obj)| match obj.kind() {
                ObjectKind::Mechanism(mech) if mech.ck_type() == mech_type => Some(*mech),
                _ => None,
            })
            .take(1)
            .next()
            .ok_or(Error::MechNotFound)
    }
}
