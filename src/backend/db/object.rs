use std::collections::HashMap;
use std::mem::size_of;

use crate::backend::Mechanism;
use crate::pkcs11;
use crate::util::{CkRawAttrTemplate, Error as UtilError};
use crate::{Error, Result};

use super::{EcKeyInfo, RsaKeyInfo};

#[derive(Clone, Copy, Debug, Hash)]
pub struct ObjectHandle(u64);

impl From<pkcs11::CK_OBJECT_HANDLE> for ObjectHandle {
    fn from(src: pkcs11::CK_OBJECT_HANDLE) -> Self {
        Self(src)
    }
}

impl From<usize> for ObjectHandle {
    fn from(src: usize) -> Self {
        Self(src as u64)
    }
}

impl From<u32> for ObjectHandle {
    fn from(src: u32) -> Self {
        Self(src as u64)
    }
}

impl From<ObjectHandle> for u64 {
    fn from(src: ObjectHandle) -> Self {
        src.0
    }
}

impl From<ObjectHandle> for usize {
    fn from(src: ObjectHandle) -> Self {
        src.0 as usize
    }
}

#[derive(Clone)]
pub enum Attr {
    Bytes(Vec<u8>),
    CkBbool([u8; size_of::<pkcs11::CK_BBOOL>()]),
    CkByte([u8; size_of::<pkcs11::CK_BYTE>()]),
    CkKeyType([u8; size_of::<pkcs11::CK_KEY_TYPE>()]),
    CkMechanismType([u8; size_of::<pkcs11::CK_MECHANISM_TYPE>()]),
    CkObjectClass([u8; size_of::<pkcs11::CK_OBJECT_CLASS>()]),
    CkUlong([u8; size_of::<pkcs11::CK_ULONG>()]),
    Sensitive,
}

impl Attr {
    const CK_TRUE: Self = Self::CkBbool([pkcs11::CK_TRUE; 1]);
    const CK_FALSE: Self = Self::CkBbool([pkcs11::CK_FALSE; 1]);

    fn len(&self) -> usize {
        match self {
            Self::CkBbool(v) => v.len(),
            Self::CkByte(v) => v.len(),
            Self::CkKeyType(v) => v.len(),
            Self::CkMechanismType(v) => v.len(),
            Self::CkObjectClass(v) => v.len(),
            Self::CkUlong(v) => v.len(),
            Self::Bytes(v) => v.len(),
            Self::Sensitive => 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::CkBbool(v) => v,
            Self::CkByte(v) => v,
            Self::CkKeyType(v) => v,
            Self::CkMechanismType(v) => v,
            Self::CkObjectClass(v) => v,
            Self::CkUlong(v) => v,
            Self::Bytes(v) => v,
            Self::Sensitive => &[0u8; 0],
        }
    }

    fn from_ck_byte(src: pkcs11::CK_BYTE) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkByte(src.to_le_bytes())
    }

    fn from_ck_key_type(src: pkcs11::CK_KEY_TYPE) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkKeyType(src.to_le_bytes())
    }

    fn from_ck_mechanism_type(src: pkcs11::CK_MECHANISM_TYPE) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkMechanismType(src.to_le_bytes())
    }

    fn from_ck_object_class(src: pkcs11::CK_OBJECT_CLASS) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkObjectClass(src.to_le_bytes())
    }

    fn from_ck_ulong(src: pkcs11::CK_ULONG) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkUlong(src.to_le_bytes())
    }
}

impl PartialEq<Attr> for Attr {
    fn eq(&self, other: &Attr) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}


#[derive(Clone, Debug)]
pub enum ObjectKind {
    RsaPrivateKey(String),
    RsaPublicKey(String),
    EcPrivateKey(String),
    EcPublicKey(String),
    Mechanism(Mechanism),
}

#[derive(Clone)]
pub struct Object {
    attrs: HashMap<pkcs11::CK_ATTRIBUTE_TYPE, Attr>,
    kind: ObjectKind,
}

impl Object {
    pub fn new_mechanism(mech: Mechanism) -> Self {
        let mut attrs = HashMap::new();
        attrs.insert(pkcs11::CKA_CLASS, Attr::from_ck_object_class(pkcs11::CKO_MECHANISM));
        attrs.insert(pkcs11::CKA_MECHANISM_TYPE, Attr::from_ck_mechanism_type(mech.ck_type()));
        Self {
            kind: ObjectKind::Mechanism(mech),
            attrs,
        }
    }

    pub fn new_rsa_private_key(info: RsaKeyInfo) -> Self {
        let mut attrs = HashMap::new();
        attrs.insert(pkcs11::CKA_CLASS, Attr::from_ck_object_class(pkcs11::CKO_PRIVATE_KEY));
        attrs.insert(pkcs11::CKA_KEY_TYPE, Attr::from_ck_key_type(pkcs11::CKK_RSA));
        attrs.insert(pkcs11::CKA_ID, Attr::from_ck_byte(info.id));
        attrs.insert(pkcs11::CKA_LABEL, Attr::Bytes(info.label.into()));
        attrs.insert(pkcs11::CKA_PRIVATE, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_SENSITIVE, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_EXTRACTABLE, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_SIGN, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_DECRYPT, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_DERIVE, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_WRAP, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_LOCAL, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_TOKEN, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_MODULUS_BITS, Attr::from_ck_ulong(info.num_bits));
        attrs.insert(pkcs11::CKA_MODULUS, Attr::Bytes(info.modulus));
        attrs.insert(
            pkcs11::CKA_PUBLIC_EXPONENT,
            Attr::Bytes(info.public_exponent),
        );
        attrs.insert(pkcs11::CKA_PRIVATE_EXPONENT, Attr::Sensitive);
        attrs.insert(pkcs11::CKA_PRIME_1, Attr::Sensitive);
        attrs.insert(pkcs11::CKA_PRIME_2, Attr::Sensitive);
        attrs.insert(pkcs11::CKA_EXPONENT_1, Attr::Sensitive);
        attrs.insert(pkcs11::CKA_EXPONENT_2, Attr::Sensitive);
        attrs.insert(pkcs11::CKA_COEFFICIENT, Attr::Sensitive);
        Self {
            kind: ObjectKind::RsaPrivateKey(info.priv_pem),
            attrs,
        }
    }

    pub fn new_rsa_public_key(info: RsaKeyInfo) -> Self {
        let mut attrs = HashMap::new();
        attrs.insert(pkcs11::CKA_CLASS, Attr::from_ck_object_class(pkcs11::CKO_PUBLIC_KEY));
        attrs.insert(pkcs11::CKA_KEY_TYPE, Attr::from_ck_key_type(pkcs11::CKK_RSA));
        attrs.insert(pkcs11::CKA_ID, Attr::from_ck_byte(info.id));
        attrs.insert(pkcs11::CKA_LABEL, Attr::Bytes(info.label.into()));
        attrs.insert(pkcs11::CKA_PRIVATE, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_SENSITIVE, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_EXTRACTABLE, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_VERIFY, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_ENCRYPT, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_DERIVE, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_WRAP, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_LOCAL, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_TOKEN, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_MODULUS_BITS, Attr::from_ck_ulong(info.num_bits));
        attrs.insert(pkcs11::CKA_MODULUS, Attr::Bytes(info.modulus));
        attrs.insert(
            pkcs11::CKA_PUBLIC_EXPONENT,
            Attr::Bytes(info.public_exponent),
        );
        Self {
            kind: ObjectKind::RsaPublicKey(info.priv_pem),
            attrs,
        }
    }

    pub fn new_ec_private_key(info: EcKeyInfo) -> Self {
        let mut attrs = HashMap::new();
        attrs.insert(pkcs11::CKA_CLASS, Attr::from_ck_object_class(pkcs11::CKO_PRIVATE_KEY));
        attrs.insert(pkcs11::CKA_KEY_TYPE, Attr::from_ck_key_type(pkcs11::CKK_EC));
        attrs.insert(pkcs11::CKA_ID, Attr::from_ck_byte(info.id));
        attrs.insert(pkcs11::CKA_LABEL, Attr::Bytes(info.label.into()));
        attrs.insert(pkcs11::CKA_PRIVATE, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_SENSITIVE, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_EXTRACTABLE, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_SIGN, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_DECRYPT, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_DERIVE, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_WRAP, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_LOCAL, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_TOKEN, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_EC_PARAMS, Attr::Bytes(info.params_x962));
        attrs.insert(pkcs11::CKA_EC_POINT, Attr::Bytes(info.point_q_x962));
        attrs.insert(pkcs11::CKA_VALUE, Attr::Sensitive);
        Self {
            kind: ObjectKind::EcPrivateKey(info.priv_pem),
            attrs,
        }
    }

    pub fn new_ec_public_key(info: EcKeyInfo) -> Self {
        let mut attrs = HashMap::new();
        attrs.insert(pkcs11::CKA_CLASS, Attr::from_ck_object_class(pkcs11::CKO_PUBLIC_KEY));
        attrs.insert(pkcs11::CKA_KEY_TYPE, Attr::from_ck_key_type(pkcs11::CKK_EC));
        attrs.insert(pkcs11::CKA_ID, Attr::from_ck_byte(info.id));
        attrs.insert(pkcs11::CKA_LABEL, Attr::Bytes(info.label.into()));
        attrs.insert(pkcs11::CKA_PRIVATE, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_SENSITIVE, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_EXTRACTABLE, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_VERIFY, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_ENCRYPT, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_DERIVE, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_WRAP, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_LOCAL, Attr::CK_FALSE);
        attrs.insert(pkcs11::CKA_TOKEN, Attr::CK_TRUE);
        attrs.insert(pkcs11::CKA_EC_PARAMS, Attr::Bytes(info.params_x962));
        attrs.insert(pkcs11::CKA_EC_POINT, Attr::Bytes(info.point_q_x962));
        Self {
            kind: ObjectKind::EcPublicKey(info.priv_pem),
            attrs,
        }
    }

    pub fn attr(&self, attr_type: pkcs11::CK_ATTRIBUTE_TYPE) -> Option<&Attr> {
        self.attrs.get(&attr_type)
    }

    pub fn kind(&self) -> &ObjectKind {
        &self.kind
    }

    pub fn is_private(&self) -> bool {
        match self.attr(pkcs11::CKA_PRIVATE) {
            Some(attr) => *attr == Attr::CK_TRUE,
            _ => false,
        }
    }

    pub fn is_mechanism(&self) -> bool {
        match self.kind {
            ObjectKind::Mechanism(_) => true,
            _ => false,
        }
    }

    pub fn match_attr_template(&self, tpl: &CkRawAttrTemplate) -> bool {
        let mut class_matched = false;
        for raw_attr in tpl.iter() {
            match self.attr(raw_attr.type_()) {
                Some(attr) => match raw_attr.val_bytes() {
                    Some(raw_bytes) => attr.as_bytes() == raw_bytes || return false,
                    None => return false,
                },
                None => return false,
            };
            class_matched = class_matched || (raw_attr.type_() == pkcs11::CKA_CLASS);
        }

        // Per the PKCS#11 v2.40 spec, mechanism objects must only match templates that
        // explicitely provide CKA_CLASS = CKO_MECHANISM.
        if self.is_mechanism() {
            class_matched
        } else {
            true
        }
    }

    pub fn fill_attr_template(&self, tpl: &mut CkRawAttrTemplate) -> Result<()> {
        let mut rcode = pkcs11::CKR_OK;

        for mut raw_attr in tpl.iter() {
            match self.attr(raw_attr.type_()) {
                Some(attr) => {
                    let sres = match attr {
                        Attr::Sensitive => {
                            rcode = pkcs11::CKR_ATTRIBUTE_SENSITIVE;
                            raw_attr.set_len(pkcs11::CK_UNAVAILABLE_INFORMATION);
                            continue;
                        }
                        a => raw_attr.set_val_bytes(a.as_bytes())
                    };
                    match sres {
                        Err(UtilError::BufTooSmall) => {
                            rcode = pkcs11::CKR_BUFFER_TOO_SMALL;
                            raw_attr.set_len(pkcs11::CK_UNAVAILABLE_INFORMATION);
                        }
                        _ => raw_attr.set_len(attr.len() as pkcs11::CK_ULONG),
                    };
                }
                None => {
                    rcode = pkcs11::CKR_ATTRIBUTE_TYPE_INVALID;
                    raw_attr.set_len(pkcs11::CK_UNAVAILABLE_INFORMATION);
                }
            };
        }
        if rcode == pkcs11::CKR_OK {
            Ok(())
        } else {
            Err(Error::CkError(rcode))
        }
    }
}
