// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vtok_common::config::Config;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::{Session, Slot, Token};
use crate::defs;
use crate::pkcs11;
use crate::{Error, Result};

/// The root device container. Holds a known number of device slots.
/// A successful provisioning operation will attach a token to the respective
/// slot. Newly created sessions are attached to their respective slots and
/// the user authenticates against the token PIN from those slots respectively.
pub struct Device {
    slots: Vec<Slot>,
    session_slot_map: HashMap<pkcs11::CK_SESSION_HANDLE, pkcs11::CK_SLOT_ID>,
    next_session_handle: pkcs11::CK_SESSION_HANDLE,
}

impl Device {
    pub fn new() -> Result<Self> {
        let config = Config::load_ro().map_err(|_| Error::GeneralError)?;

        let mut slots = Vec::with_capacity(defs::MAX_SLOTS);
        for (slot_id, slot_config) in config.slots().iter().enumerate() {
            slots.push(match slot_config {
                None => Slot::new(slot_id as pkcs11::CK_SLOT_ID),
                Some(token_config) => Slot::new_with_token(
                    slot_id as pkcs11::CK_SLOT_ID,
                    Token::from_config(slot_id as pkcs11::CK_SLOT_ID, &token_config)
                        .map_err(Error::TokenError)?,
                ),
            });
        }

        Ok(Self {
            slots,
            session_slot_map: HashMap::new(),
            next_session_handle: 1,
        })
    }

    pub fn ck_info(&self) -> pkcs11::CK_INFO {
        pkcs11::CK_INFO {
            cryptokiVersion: defs::CRYPTOKI_VERSION,
            manufacturerID: ck_padded_str!(defs::DEVICE_MANUFACTURER, 32),
            flags: 0,
            libraryDescription: ck_padded_str!(defs::DEVICE_DESCRIPTION, 32),
            libraryVersion: defs::DEVICE_VERSION,
        }
    }

    pub fn ck_slot_ids(&self, must_have_token: bool) -> Vec<pkcs11::CK_SLOT_ID> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(idx, slot)| {
                if must_have_token && !slot.has_token() {
                    None
                } else {
                    Some(idx as pkcs11::CK_SLOT_ID)
                }
            })
            .collect()
    }

    pub fn slot_count(&self, must_have_token: bool) -> usize {
        self.slots
            .iter()
            .filter(|slot| !must_have_token || slot.has_token())
            .count()
    }

    pub fn open_session(
        &mut self,
        slot_id: pkcs11::CK_SLOT_ID,
    ) -> Result<pkcs11::CK_SESSION_HANDLE> {
        let handle = self.next_session_handle;

        self.slot_mut(slot_id)
            .ok_or(Error::CkError(pkcs11::CKR_SLOT_ID_INVALID))?
            .token_mut()
            .ok_or(Error::CkError(pkcs11::CKR_TOKEN_NOT_PRESENT))?
            .open_session(handle)
            .map_err(Error::TokenError)?;

        self.session_slot_map.insert(handle, slot_id);
        self.next_session_handle += 1;

        Ok(handle)
    }

    pub fn close_session(&mut self, handle: pkcs11::CK_SESSION_HANDLE) -> Result<()> {
        let slot_id = *self
            .session_slot_map
            .get(&handle)
            .ok_or(Error::SessionHandleInvalid)?;
        self.token_mut(slot_id)?
            .close_session(handle)
            .map_err(Error::TokenError)?;
        self.session_slot_map.remove(&handle);
        Ok(())
    }

    pub fn close_all_slot_sessions(&mut self, slot_id: pkcs11::CK_SLOT_ID) -> Result<()> {
        self.token_mut(slot_id)
            .map(|tok| tok.close_all_sessions())?;
        self.session_slot_map.retain(|_, &mut sid| sid != slot_id);
        Ok(())
    }

    pub fn session(&self, handle: pkcs11::CK_SESSION_HANDLE) -> Option<Arc<Mutex<Session>>> {
        self.session_slot_map
            .get(&handle)
            .and_then(|&slot_id| self.token(slot_id).ok())
            .and_then(|token| token.session(handle))
    }

    pub fn session_mut(&mut self, handle: pkcs11::CK_SESSION_HANDLE) -> Option<Arc<Mutex<Session>>> {
        let slot_id = *self.session_slot_map.get(&handle)?;

        //todo: modify slots if necessary
        match self.token(slot_id) {
            Ok(token) => token.session(handle),
            Err(_) => None,
        }
    }

    pub fn login(&mut self, session_handle: pkcs11::CK_SESSION_HANDLE, pin: &str) -> Result<()> {
        let slot_id = *self
            .session_slot_map
            .get(&session_handle)
            .ok_or(Error::SessionHandleInvalid)?;
        self.token_mut(slot_id)?
            .login(session_handle, pin)
            .map_err(Error::TokenError)
    }

    pub fn logout(&mut self, session_handle: pkcs11::CK_SESSION_HANDLE) -> Result<()> {
        let slot_id = *self
            .session_slot_map
            .get(&session_handle)
            .ok_or(Error::SessionHandleInvalid)?;
        self.token_mut(slot_id)?
            .logout(session_handle)
            .map_err(Error::TokenError)
    }

    pub fn slot(&self, slot_id: pkcs11::CK_SLOT_ID) -> Option<&Slot> {
        if (slot_id as usize) >= self.slots.len() {
            return None;
        }
        Some(&self.slots[slot_id as usize])
    }

    pub fn slot_mut(&mut self, slot_id: pkcs11::CK_SLOT_ID) -> Option<&mut Slot> {
        if (slot_id as usize) >= self.slots.len() {
            return None;
        }
        Some(&mut self.slots[slot_id as usize])
    }

    pub fn token(&self, slot_id: pkcs11::CK_SLOT_ID) -> Result<&Token> {
        self.slot(slot_id)
            .ok_or(Error::SlotIdInvalid)
            .and_then(|slot| slot.token().ok_or(Error::TokenNotPresent))
    }

    pub fn token_mut(&mut self, slot_id: pkcs11::CK_SLOT_ID) -> Result<&mut Token> {
        self.slot_mut(slot_id)
            .ok_or(Error::SlotIdInvalid)
            .and_then(|slot| slot.token_mut().ok_or(Error::TokenNotPresent))
    }
}
