use std::iter::Iterator;

use super::Error;
use crate::pkcs11;

pub struct CkRawAttr(pkcs11::CK_ATTRIBUTE_PTR);

impl CkRawAttr {
    pub unsafe fn from_raw_ptr_unchecked(ptr: pkcs11::CK_ATTRIBUTE_PTR) -> Self {
        Self(ptr)
    }

    pub fn type_(&self) -> pkcs11::CK_ATTRIBUTE_TYPE {
        unsafe { (*self.0).type_ }
    }

    pub fn val_bytes(&self) -> Option<&[u8]> {
        let val_ptr = unsafe { (*self.0).pValue };
        if val_ptr.is_null() {
            return None;
        }
        unsafe {
            Some(std::slice::from_raw_parts(
                val_ptr as *const u8,
                self.len() as usize,
            ))
        }
    }

    pub fn len(&self) -> pkcs11::CK_ULONG {
        unsafe { (*self.0).ulValueLen }
    }

    pub fn set_len(&mut self, len: pkcs11::CK_ULONG) {
        unsafe {
            (*self.0).ulValueLen = len;
        }
    }

    pub fn set_val_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        unsafe {
            if (*self.0).pValue.is_null() {
                return Err(Error::NullPtrDeref);
            }
            if bytes.len() > (*self.0).ulValueLen as usize {
                return Err(Error::BufTooSmall);
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), (*self.0).pValue as *mut u8, bytes.len());
        }
        Ok(())
    }
}

pub struct CkRawAttrTemplate {
    ptr: pkcs11::CK_ATTRIBUTE_PTR,
    count: usize,
}

impl CkRawAttrTemplate {
    pub unsafe fn from_raw_ptr_unchecked(ptr: pkcs11::CK_ATTRIBUTE_PTR, count: usize) -> Self {
        Self { ptr, count }
    }

    pub fn attr_wrapper(&self, index: usize) -> Option<CkRawAttr> {
        if index >= self.count {
            return None;
        }
        Some(unsafe { CkRawAttr::from_raw_ptr_unchecked(self.ptr.add(index)) })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn iter(&self) -> CkRawAttrTemplateIter {
        CkRawAttrTemplateIter {
            tpl: self,
            index: 0,
        }
    }
}

pub struct CkRawAttrTemplateIter<'a> {
    tpl: &'a CkRawAttrTemplate,
    index: usize,
}

impl<'a> Iterator for CkRawAttrTemplateIter<'a> {
    type Item = CkRawAttr;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.tpl.len() {
            let ret = self.tpl.attr_wrapper(self.index);
            self.index += 1;
            ret
        } else {
            None
        }
    }
}

pub struct CkRawMechanism {
    ptr: *mut pkcs11::CK_MECHANISM,
}
pub trait MechParams {}
impl MechParams for pkcs11::CK_RSA_PKCS_PSS_PARAMS {}

impl CkRawMechanism {
    pub unsafe fn from_raw_ptr_unchecked(ptr: *mut pkcs11::CK_MECHANISM) -> Self {
        Self { ptr }
    }

    pub fn type_(&self) -> pkcs11::CK_MECHANISM_TYPE {
        unsafe { (*self.ptr).mechanism }
    }

    // Note: marking this unsafe, even if it breaks our pattern of using object constructors
    // to cover unsafe FFI code.
    // Reading the wrong data type is bad, mkay?
    pub unsafe fn params<T: MechParams>(&self) -> Result<Option<T>, Error> {
        let param_ptr = (*self.ptr).pParameter;
        let param_len = (*self.ptr).ulParameterLen;
        if param_ptr.is_null() || param_len == 0 {
            return Ok(None);
        }
        if std::mem::size_of::<T>() != param_len as usize {
            return Err(Error::MechParamTypeMismatch);
        }
        Ok(Some(std::ptr::read(param_ptr as *const T)))
    }
}
