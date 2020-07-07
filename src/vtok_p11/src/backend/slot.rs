use super::token::Token;
use crate::defs;
use crate::pkcs11;

/// Device slot container. A token shall be attached to it
/// (i.e. CKF_TOKEN_PRESENT bit set) once it is successfully
/// provisioned with a database.
pub struct Slot {
    _id: pkcs11::CK_SLOT_ID,
    token: Option<Token>,
}

impl Slot {
    pub fn _new(id: pkcs11::CK_SLOT_ID) -> Self {
        Self {
            _id: id,
            token: None,
        }
    }

    pub fn new_with_default_token(id: pkcs11::CK_SLOT_ID) -> Self {
        Self {
            _id: id,
            token: Some(Token::new(id)),
        }
    }

    pub fn ck_info(&self) -> pkcs11::CK_SLOT_INFO {
        let mut flags = 0;
        if self.has_token() {
            flags |= pkcs11::CKF_TOKEN_PRESENT;
        }
        pkcs11::CK_SLOT_INFO {
            slotDescription: ck_padded_str!(defs::SLOT_DESCRIPTION, 64),
            manufacturerID: ck_padded_str!(defs::SLOT_MANUFACTURER, 32),
            flags,
            hardwareVersion: defs::SLOT_HARDWARE_VERSION,
            firmwareVersion: defs::SLOT_FIRMWARE_VERSION,
        }
    }

    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    pub fn token(&self) -> Option<&Token> {
        self.token.as_ref()
    }

    pub fn token_mut(&mut self) -> Option<&mut Token> {
        self.token.as_mut()
    }
}
