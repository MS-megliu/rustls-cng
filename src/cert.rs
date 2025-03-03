//! Wrapper struct for Windows CERT_CONTEXT

use std::{mem, ptr, slice, sync::Arc};

use windows_sys::Win32::Security::Cryptography::*;

use crate::{error::CngError, key::NCryptKey, Result};

const HCCE_LOCAL_MACHINE: HCERTCHAINENGINE = 0x1 as HCERTCHAINENGINE;

#[derive(Debug)]
enum InnerContext {
    Owned(*const CERT_CONTEXT),
    Borrowed(*const CERT_CONTEXT),
}

unsafe impl Send for InnerContext {}
unsafe impl Sync for InnerContext {}

impl InnerContext {
    fn inner(&self) -> *const CERT_CONTEXT {
        match self {
            Self::Owned(handle) => *handle,
            Self::Borrowed(handle) => *handle,
        }
    }
}

impl Drop for InnerContext {
    fn drop(&mut self) {
        match self {
            Self::Owned(handle) => unsafe {
                CertFreeCertificateContext(*handle);
            },
            Self::Borrowed(_) => {}
        }
    }
}

/// CertContext wraps CERT_CONTEXT structure for high-level certificate operations
#[derive(Debug, Clone)]
pub struct CertContext(Arc<InnerContext>);

impl CertContext {
    /// Construct CertContext as an owned object which automatically frees the inner handle
    pub fn new_owned(context: *const CERT_CONTEXT) -> Self {
        Self(Arc::new(InnerContext::Owned(context)))
    }

    /// Construct CertContext as a borrowed object which does not free the inner handle
    pub fn new_borrowed(context: *const CERT_CONTEXT) -> Self {
        Self(Arc::new(InnerContext::Borrowed(context)))
    }

    /// Return a reference to the inner handle
    pub fn inner(&self) -> &CERT_CONTEXT {
        unsafe { &*self.0.inner() }
    }

    /// Attempt to acquire a CNG private key from this context.
    /// The `silent` parameter indicates whether to suppress the user prompts.
    pub fn acquire_key(&self, silent: bool) -> Result<NCryptKey> {
        let mut handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
        let mut key_spec = CERT_KEY_SPEC::default();

        let flags =
            if silent { CRYPT_ACQUIRE_SILENT_FLAG } else { 0 } | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG;

        unsafe {
            let result = CryptAcquireCertificatePrivateKey(
                self.inner(),
                flags,
                ptr::null(),
                &mut handle,
                &mut key_spec,
                ptr::null_mut(),
            ) != 0;
            if result {
                let mut key = NCryptKey::new_owned(handle);
                key.set_silent(silent);
                Ok(key)
            } else {
                Err(CngError::from_win32_error())
            }
        }
    }

    /// Return DER-encoded X.509 certificate
    pub fn as_der(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self.inner().pbCertEncoded,
                self.inner().cbCertEncoded as usize,
            )
        }
    }

    /// Return DER-encoded X.509 certificate chain.
    // (1) exclude the root. (2) check leaf cert to determine to use HKLM engine or HKCU engine
    pub fn as_chain_der(&self) -> Result<Vec<Vec<u8>>> {
        unsafe {
            let param = CERT_CHAIN_PARA {
                cbSize: mem::size_of::<CERT_CHAIN_PARA>() as u32,
                RequestedUsage: std::mem::zeroed(),
            };
            let mut context: *mut CERT_CHAIN_CONTEXT = ptr::null_mut();
            let mut dw_access_state_flags: u32 = 0;
            let mut cb_data = mem::size_of::<u32>() as u32;

            let chain_engine = if CertGetCertificateContextProperty(
                self.inner(),
                CERT_ACCESS_STATE_PROP_ID,
                &mut dw_access_state_flags as *mut _ as *mut _,
                &mut cb_data as *mut _,
            ) != 0
                && (dw_access_state_flags & CERT_ACCESS_STATE_LM_SYSTEM_STORE_FLAG) != 0
            {
                HCCE_LOCAL_MACHINE
            } else {
                HCERTCHAINENGINE::default()
            };

            let result = CertGetCertificateChain(
                chain_engine,
                self.inner(),
                ptr::null(),
                ptr::null_mut(),
                &param,
                0,
                ptr::null(),
                &mut context,
            ) != 0;

            if result {
                let mut chain = vec![];

                if (*context).cChain > 0 {
                    let chain_ptr = *(*context).rgpChain;
                    let elements = slice::from_raw_parts(
                        (*chain_ptr).rgpElement,
                        (*chain_ptr).cElement as usize,
                    );

                    for (index, element) in elements.iter().enumerate() {
                        if index != 0 {
                            if 0 != ((**element).TrustStatus.dwInfoStatus
                                & CERT_TRUST_IS_SELF_SIGNED)
                            {
                                break;
                            }
                        }

                        let context = (**element).pCertContext;
                        chain.push(Self::new_borrowed(context).as_der().to_vec());
                    }
                }

                CertFreeCertificateChain(&*context);
                Ok(chain)
            } else {
                Err(CngError::from_win32_error())
            }
        }
    }
}
