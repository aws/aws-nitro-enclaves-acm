#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use crate::pkcs11;

/// Not-Yet-Implemented Cryptoki functions
/// See PKCS#11 v2.40 for information on these functions

pub extern "C" fn C_InitPIN(
    hSession: pkcs11::CK_SESSION_HANDLE,
    uPin: pkcs11::CK_UTF8CHAR_PTR,
    ulPinLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_InitPIN() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_SetPIN(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pOldPin: pkcs11::CK_UTF8CHAR_PTR,
    ulOldLen: pkcs11::CK_ULONG,
    pNewPin: pkcs11::CK_UTF8CHAR_PTR,
    ulNewLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_SetPIN() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_GetOperationState(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pOperationState: pkcs11::CK_BYTE_PTR,
    pulOperationStateLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_GetOperationState() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_SetOperationState(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pOperationState: pkcs11::CK_BYTE_PTR,
    ulOperationStateLen: pkcs11::CK_ULONG,
    hEncryptionKey: pkcs11::CK_OBJECT_HANDLE,
    hAuthenticationKey: pkcs11::CK_OBJECT_HANDLE,
) -> pkcs11::CK_RV {
    trace!("C_SetOperationState() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_CreateObject(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pTemplate: pkcs11::CK_ATTRIBUTE_PTR,
    ulCount: pkcs11::CK_ULONG,
    phObject: pkcs11::CK_OBJECT_HANDLE_PTR,
) -> pkcs11::CK_RV {
    trace!("C_CreateObject() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_CopyObject(
    hSession: pkcs11::CK_SESSION_HANDLE,
    hObject: pkcs11::CK_OBJECT_HANDLE,
    pTemplate: pkcs11::CK_ATTRIBUTE_PTR,
    ulCount: pkcs11::CK_ULONG,
    phNewObject: pkcs11::CK_OBJECT_HANDLE_PTR,
) -> pkcs11::CK_RV {
    trace!("C_CopyObject() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DestroyObject(
    hSession: pkcs11::CK_SESSION_HANDLE,
    hObject: pkcs11::CK_OBJECT_HANDLE,
) -> pkcs11::CK_RV {
    trace!("C_DestroyObject() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_SetAttributeValue(
    hSession: pkcs11::CK_SESSION_HANDLE,
    hObject: pkcs11::CK_OBJECT_HANDLE,
    pTemplate: pkcs11::CK_ATTRIBUTE_PTR,
    ulCount: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_SetAttributeValue() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_EncryptUpdate(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pPart: pkcs11::CK_BYTE_PTR,
    ulPartLen: pkcs11::CK_ULONG,
    pEncryptedPart: pkcs11::CK_BYTE_PTR,
    pulEncryptedPartLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_EncryptUpdate() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_EncryptFinal(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pLastEncryptedPart: pkcs11::CK_BYTE_PTR,
    pulLastEncryptedPartLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_EncryptFinal() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DecryptUpdate(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pEncryptedPart: pkcs11::CK_BYTE_PTR,
    ulEncryptedPartLen: pkcs11::CK_ULONG,
    pPart: pkcs11::CK_BYTE_PTR,
    pulPartLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_DecryptUpdate() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DecryptFinal(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pLastPart: pkcs11::CK_BYTE_PTR,
    pulLastPartLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_DecryptFinal() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DigestKey(
    hSession: pkcs11::CK_SESSION_HANDLE,
    hKey: pkcs11::CK_OBJECT_HANDLE,
) -> pkcs11::CK_RV {
    trace!("C_DigestKey() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_SignRecoverInit(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: pkcs11::CK_MECHANISM_PTR,
    hKey: pkcs11::CK_OBJECT_HANDLE,
) -> pkcs11::CK_RV {
    trace!("C_SignRecoverInit() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_SignRecover(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pData: pkcs11::CK_BYTE_PTR,
    ulDataLen: pkcs11::CK_ULONG,
    pSignature: pkcs11::CK_BYTE_PTR,
    pulSignatureLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_SignRecover() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_VerifyRecoverInit(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: pkcs11::CK_MECHANISM_PTR,
    hKey: pkcs11::CK_OBJECT_HANDLE,
) -> pkcs11::CK_RV {
    trace!("C_VerifyRecoverInit() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_VerifyRecover(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pSignature: pkcs11::CK_BYTE_PTR,
    ulSignatureLen: pkcs11::CK_ULONG,
    pData: pkcs11::CK_BYTE_PTR,
    pulDataLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_VerifyRecover() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DigestEncryptUpdate(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pPart: pkcs11::CK_BYTE_PTR,
    ulPartLen: pkcs11::CK_ULONG,
    pEncryptedPart: pkcs11::CK_BYTE_PTR,
    pulEncryptedPartLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_DigestEncryptUpdate() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DecryptDigestUpdate(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pEncryptedPart: pkcs11::CK_BYTE_PTR,
    ulEncryptedPartLen: pkcs11::CK_ULONG,
    pPart: pkcs11::CK_BYTE_PTR,
    pulPartLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_DecryptDigestUpdate() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_SignEncryptUpdate(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pPart: pkcs11::CK_BYTE_PTR,
    ulPartLen: pkcs11::CK_ULONG,
    pEncryptedPart: pkcs11::CK_BYTE_PTR,
    pulEncryptedPartLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_SignEncryptUpdate() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DecryptVerifyUpdate(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pEncryptedPart: pkcs11::CK_BYTE_PTR,
    ulEncryptedPartLen: pkcs11::CK_ULONG,
    pPart: pkcs11::CK_BYTE_PTR,
    pulPartLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_DecryptVerifyUpdate() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_GenerateKey(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: pkcs11::CK_MECHANISM_PTR,
    pTemplate: pkcs11::CK_ATTRIBUTE_PTR,
    ulCount: pkcs11::CK_ULONG,
    phKey: pkcs11::CK_OBJECT_HANDLE_PTR,
) -> pkcs11::CK_RV {
    trace!("C_GenerateKey() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_GenerateKeyPair(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: pkcs11::CK_MECHANISM_PTR,
    pPublicKeyTemplate: pkcs11::CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: pkcs11::CK_ULONG,
    pPrivateKeyTemplate: pkcs11::CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: pkcs11::CK_ULONG,
    phPublicKey: pkcs11::CK_OBJECT_HANDLE_PTR,
    phPrivateKey: pkcs11::CK_OBJECT_HANDLE_PTR,
) -> pkcs11::CK_RV {
    trace!("C_GenerateKeyPair() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_WrapKey(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: pkcs11::CK_MECHANISM_PTR,
    hWrappingKey: pkcs11::CK_OBJECT_HANDLE,
    hKey: pkcs11::CK_OBJECT_HANDLE,
    pWrappedKey: pkcs11::CK_BYTE_PTR,
    pulWrappedKeyLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_WrapKey() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_UnwrapKey(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: pkcs11::CK_MECHANISM_PTR,
    hUnwrappingKey: pkcs11::CK_OBJECT_HANDLE,
    pWrappedKey: pkcs11::CK_BYTE_PTR,
    ulWrappedKeyLen: pkcs11::CK_ULONG,
    pTemplate: pkcs11::CK_ATTRIBUTE_PTR,
    ulAttributeCount: pkcs11::CK_ULONG,
    phKey: pkcs11::CK_OBJECT_HANDLE_PTR,
) -> pkcs11::CK_RV {
    trace!("C_UnwrapKey() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DeriveKey(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: pkcs11::CK_MECHANISM_PTR,
    hBaseKey: pkcs11::CK_OBJECT_HANDLE,
    pTemplate: pkcs11::CK_ATTRIBUTE_PTR,
    ulAttributeCount: pkcs11::CK_ULONG,
    phKey: pkcs11::CK_OBJECT_HANDLE_PTR,
) -> pkcs11::CK_RV {
    trace!("C_DeriveKey() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_SeedRandom(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pSeed: pkcs11::CK_BYTE_PTR,
    ulSeedLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_SeedRandom() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_GenerateRandom(
    hSession: pkcs11::CK_SESSION_HANDLE,
    RandomData: pkcs11::CK_BYTE_PTR,
    ulRandomLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_GenerateRandom() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_WaitForSlotEvent(
    flags: pkcs11::CK_FLAGS,
    pSlot: pkcs11::CK_SLOT_ID_PTR,
    pReserved: pkcs11::CK_VOID_PTR,
) -> pkcs11::CK_RV {
    trace!("C_WaitForSlotEvent() called - NYI");
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}
