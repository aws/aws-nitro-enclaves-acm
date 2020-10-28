// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vtok_common::config;

use crate::crypto;
use crate::defs;
use crate::pkcs11;

pub mod object;

pub use object::{Object, ObjectHandle, ObjectKind};

// NOTE: for now, we use these *Info structs to construct key objects. The source PEM is
// preserved, so that a crypto::Pkey (an EVP_PKEY wrapper) can be constructed whenever
// it is needed (e.g. at operation context initialization).
// If the PEM to EVP_PKEY conversion turns out to impact performance, we could construct
// the crypto::Pkey object at DB creation time, and replace the *Info structs with it,
// provided we also implement a proper cloning mechanism for crypto::Pkey. This is needed
// in order to make sure that each session gets its own copy of each key, and maintain
// thread safety.
// Cloning could be done via RSAPrivateKey_dup() and EC_KEY_dup(), together with a TryClone
// trait, since these operations can fail.
#[derive(Clone)]
pub struct RsaKeyInfo {
    pub priv_pem: String,
    pub id: pkcs11::CK_BYTE,
    pub label: String,
    pub num_bits: pkcs11::CK_ULONG,
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
}

#[derive(Clone)]
pub struct EcKeyInfo {
    pub priv_pem: String,
    pub id: pkcs11::CK_BYTE,
    pub label: String,
    pub params_x962: Vec<u8>,
    pub point_q_x962: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub enum Error {
    GeneralError,
    CryptoError(crypto::Error),
    PemError(crypto::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct Db {
    token_pin: String,
    objects: Vec<Object>,
}

impl Db {
    pub fn from_token_config(token_config: &config::Token) -> Result<Self> {
        let mut objects = Vec::new();

        for mech in defs::TOKEN_MECH_LIST.iter() {
            objects.push(Object::new_mechanism(*mech));
        }

        for key_config in token_config.private_keys.iter() {
            let pkey =
                crypto::Pkey::from_private_pem(key_config.pem.as_str()).map_err(Error::PemError)?;
            match pkey.algo().map_err(Error::CryptoError)? {
                crypto::KeyAlgo::Rsa => {
                    let info = RsaKeyInfo {
                        id: key_config.id,
                        label: key_config.label.clone(),
                        priv_pem: key_config.pem.to_string(),
                        num_bits: pkey.num_bits().map_err(Error::CryptoError)? as u64,
                        modulus: pkey.rsa_modulus().map_err(Error::CryptoError)?,
                        public_exponent: pkey.rsa_public_exponent().map_err(Error::CryptoError)?,
                    };
                    objects.push(Object::new_rsa_private_key(info.clone()));
                    objects.push(Object::new_rsa_public_key(info));
                }
                crypto::KeyAlgo::Ec => {
                    let info = EcKeyInfo {
                        id: key_config.id,
                        label: key_config.label.clone(),
                        priv_pem: key_config.pem.to_string(),
                        params_x962: pkey.ec_params_x962().map_err(Error::CryptoError)?,
                        point_q_x962: pkey.ec_point_q_x962().map_err(Error::CryptoError)?,
                    };
                    objects.push(Object::new_ec_private_key(info.clone()));
                    objects.push(Object::new_ec_public_key(info));
                }
            }
        }

        Ok(Self {
            token_pin: token_config.pin.clone(),
            objects,
        })
    }

    pub fn enumerate(&self) -> impl Iterator<Item = (ObjectHandle, &Object)> {
        self.objects
            .iter()
            .enumerate()
            .map(|(i, o)| (ObjectHandle::from(i), o))
    }

    pub fn object(&self, handle: ObjectHandle) -> Option<&Object> {
        if self.objects.len() <= usize::from(handle) {
            return None;
        }
        Some(&self.objects[usize::from(handle)])
    }

    pub fn token_pin(&self) -> &str {
        self.token_pin.as_str()
    }
}
