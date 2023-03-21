mod errors;

use crate::errors::{LoadRootCertificateError, WolfCleanupError, WolfInitError};
use wolfssl_sys::raw_bindings;

/// Wraps [`wolfSSL_Init`][0]
///
/// Note that this is also internally during initialization by
/// [`WolfContextBuilder`].
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_init
pub fn wolf_init() -> Result<(), WolfInitError> {
    match unsafe { raw_bindings::wolfSSL_Init() } {
        raw_bindings::WOLFSSL_SUCCESS => Ok(()),
        raw_bindings::BAD_MUTEX_E => Err(WolfInitError::Mutex),
        raw_bindings::WC_INIT_E => Err(WolfInitError::WolfCrypt),
        e => panic!("Unexpected return value from `wolfSSL_Init`. Got {e}"),
    }
}

/// Wraps [`wolfSSL_Cleanup`][0]
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_cleanup
pub fn wolf_cleanup() -> Result<(), WolfCleanupError> {
    match unsafe { raw_bindings::wolfSSL_Cleanup() } {
        raw_bindings::WOLFSSL_SUCCESS => Ok(()),
        raw_bindings::BAD_MUTEX_E => Err(WolfCleanupError::Mutex),
        e => panic!("Unexpected return value from `wolfSSL_Cleanup. Got {e}`"),
    }
}

// We support these for now. The methods here correspond directly to
// the build flags we currently set in `build.rs`
pub enum WolfMethod {
    DtlsClient,
    DtlsClientV1_2,
    DtlsClientV1_3,
    DtlsServer,
    DtlsServerV1_2,
    DtlsServerV1_3,
    TlsClient,
    TlsClientV1_2,
    TlsClientV1_3,
    TlsServer,
    TlsServerV1_2,
    TlsServerV1_3,
}

impl WolfMethod {
    pub fn into_method_ptr(self) -> Option<*mut raw_bindings::WOLFSSL_METHOD> {
        let ptr = match self {
            Self::DtlsClient => unsafe { raw_bindings::wolfDTLS_client_method() },
            Self::DtlsClientV1_2 => unsafe { raw_bindings::wolfDTLSv1_2_client_method() },
            Self::DtlsClientV1_3 => unsafe { raw_bindings::wolfDTLSv1_3_client_method() },
            Self::DtlsServer => unsafe { raw_bindings::wolfDTLS_server_method() },
            Self::DtlsServerV1_2 => unsafe { raw_bindings::wolfDTLSv1_2_server_method() },
            Self::DtlsServerV1_3 => unsafe { raw_bindings::wolfDTLSv1_3_server_method() },
            Self::TlsClient => unsafe { raw_bindings::wolfTLS_client_method() },
            Self::TlsClientV1_2 => unsafe { raw_bindings::wolfTLSv1_2_client_method() },
            Self::TlsClientV1_3 => unsafe { raw_bindings::wolfTLSv1_3_client_method() },
            Self::TlsServer => unsafe { raw_bindings::wolfTLS_server_method() },
            Self::TlsServerV1_2 => unsafe { raw_bindings::wolfTLSv1_2_server_method() },
            Self::TlsServerV1_3 => unsafe { raw_bindings::wolfTLSv1_3_server_method() },
        };

        if !ptr.is_null() {
            Some(ptr)
        } else {
            None
        }
    }
}

pub enum RootCertificate<'a> {
    PemBuffer(&'a [u8]),
    Asn1Buffer(&'a [u8]),
    PemFileOrDirectory(&'a std::path::Path),
}

pub enum Secret<'a> {
    Asn1Buffer(&'a [u8]),
    Asn1File(&'a std::path::Path),
    PemBuffer(&'a [u8]),
    PemFile(&'a std::path::Path),
}

pub struct WolfContextBuilder(*mut raw_bindings::WOLFSSL_CTX);

impl WolfContextBuilder {
    /// Invokes [`wolfSSL_CTX_new`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_new
    pub fn new(method: WolfMethod) -> Option<Self> {
        let method_fn = method.into_method_ptr()?;

        let ctx = unsafe { raw_bindings::wolfSSL_CTX_new(method_fn) };

        if !ctx.is_null() {
            Some(Self(ctx))
        } else {
            None
        }
    }

    /// Wraps [`wolfSSL_CTX_load_verify_buffer`][0] and [`wolfSSL_CTX_load_verify_locations`][1]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_buffer
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_locations
    pub fn with_root_certificate(
        self,
        root: RootCertificate,
    ) -> Result<Self, LoadRootCertificateError> {
        use raw_bindings::{
            wolfSSL_CTX_load_verify_buffer, wolfSSL_CTX_load_verify_locations,
            WOLFSSL_FILETYPE_ASN1, WOLFSSL_FILETYPE_PEM, WOLFSSL_SUCCESS,
        };

        let result = match root {
            RootCertificate::Asn1Buffer(buf) => unsafe {
                wolfSSL_CTX_load_verify_buffer(
                    self.0,
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            RootCertificate::PemBuffer(buf) => unsafe {
                wolfSSL_CTX_load_verify_buffer(
                    self.0,
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_PEM,
                )
            },
            RootCertificate::PemFileOrDirectory(path) => {
                let is_dir = path.is_dir();
                let path =
                    std::ffi::CString::new(path.to_str().ok_or(LoadRootCertificateError::Path)?)
                        .map_err(|_| LoadRootCertificateError::Path)?;
                if is_dir {
                    unsafe {
                        wolfSSL_CTX_load_verify_locations(
                            self.0,
                            std::ptr::null(),
                            path.as_c_str().as_ptr(),
                        )
                    }
                } else {
                    unsafe {
                        wolfSSL_CTX_load_verify_locations(
                            self.0,
                            path.as_c_str().as_ptr(),
                            std::ptr::null(),
                        )
                    }
                }
            }
        };

        if result == WOLFSSL_SUCCESS {
            Ok(self)
        } else {
            Err(LoadRootCertificateError::from(result))
        }
    }

    /// Wraps [`wolfSSL_CTX_set_cipher_list`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_ctx_set_cipher_list
    pub fn with_cipher_list(self, cipher_list: &str) -> Option<Self> {
        let cipher_list = std::ffi::CString::new(cipher_list).ok()?;
        let result = unsafe {
            raw_bindings::wolfSSL_CTX_set_cipher_list(self.0, cipher_list.as_c_str().as_ptr())
        };
        if result == raw_bindings::WOLFSSL_SUCCESS {
            Some(self)
        } else {
            None
        }
    }

    /// Wraps [`wolfSSL_CTX_use_certificate_file`][0] and [`wolfSSL_CTX_use_certificate_buffer`][1]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_certificate_file
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_certificate_buffer
    pub fn with_certificate(self, secret: Secret) -> Option<Self> {
        use raw_bindings::{
            wolfSSL_CTX_use_certificate_buffer, wolfSSL_CTX_use_certificate_file,
            WOLFSSL_FILETYPE_ASN1, WOLFSSL_FILETYPE_PEM, WOLFSSL_SUCCESS,
        };

        let result = match secret {
            Secret::Asn1Buffer(buf) => unsafe {
                wolfSSL_CTX_use_certificate_buffer(
                    self.0,
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::Asn1File(path) => unsafe {
                let file = std::ffi::CString::new(path.to_str()?).ok()?;
                wolfSSL_CTX_use_certificate_file(
                    self.0,
                    file.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::PemBuffer(buf) => unsafe {
                wolfSSL_CTX_use_certificate_buffer(
                    self.0,
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_PEM,
                )
            },
            Secret::PemFile(path) => unsafe {
                let file = std::ffi::CString::new(path.to_str()?).ok()?;
                wolfSSL_CTX_use_certificate_file(
                    self.0,
                    file.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_PEM,
                )
            },
        };

        if result == WOLFSSL_SUCCESS {
            Some(self)
        } else {
            None
        }
    }

    /// Wraps [`wolfSSL_CTX_use_PrivateKey_file`][0] and [`wolfSSL_CTX_use_PrivateKey_buffer`][1]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_privatekey_file
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_privatekey_buffer
    pub fn with_private_key(self, secret: Secret) -> Option<Self> {
        use raw_bindings::{
            wolfSSL_CTX_use_PrivateKey_buffer, wolfSSL_CTX_use_PrivateKey_file,
            WOLFSSL_FILETYPE_ASN1, WOLFSSL_FILETYPE_PEM, WOLFSSL_SUCCESS,
        };

        let result = match secret {
            Secret::Asn1Buffer(buf) => unsafe {
                wolfSSL_CTX_use_PrivateKey_buffer(
                    self.0,
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::Asn1File(path) => unsafe {
                let path = std::ffi::CString::new(path.to_str()?).ok()?;
                wolfSSL_CTX_use_PrivateKey_file(
                    self.0,
                    path.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::PemBuffer(buf) => unsafe {
                wolfSSL_CTX_use_PrivateKey_buffer(
                    self.0,
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_PEM,
                )
            },
            Secret::PemFile(path) => unsafe {
                let path = std::ffi::CString::new(path.to_str()?).ok()?;
                wolfSSL_CTX_use_PrivateKey_file(
                    self.0,
                    path.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_PEM,
                )
            },
        };

        if result == WOLFSSL_SUCCESS {
            Some(self)
        } else {
            None
        }
    }

    /// Wraps `wolfSSL_CTX_UseSecureRenegotiation`
    ///
    // TODO (pangt): I can't seem to find documentation online for this.
    // this might also prompt a more general review of how we should
    // be checking for and handling errors (i.e; should we just
    // collect all error codes and throw it back up instead of
    // wrapping it in an enum?)
    pub fn with_secure_renegotiation(self) -> Option<Self> {
        let result = unsafe { raw_bindings::wolfSSL_CTX_UseSecureRenegotiation(self.0) };
        if result == raw_bindings::WOLFSSL_SUCCESS {
            Some(self)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test]
    fn wolf_init_test() {
        wolf_init().unwrap();
    }

    #[test]
    fn wolf_cleanup_test() {
        wolf_cleanup().unwrap();
    }

    #[test_case(WolfMethod::DtlsClient)]
    #[test_case(WolfMethod::DtlsClientV1_2)]
    #[test_case(WolfMethod::DtlsClientV1_3)]
    #[test_case(WolfMethod::DtlsServer)]
    #[test_case(WolfMethod::DtlsServerV1_2)]
    #[test_case(WolfMethod::DtlsServerV1_3)]
    #[test_case(WolfMethod::TlsClient)]
    #[test_case(WolfMethod::TlsClientV1_2)]
    #[test_case(WolfMethod::TlsClientV1_3)]
    #[test_case(WolfMethod::TlsServer)]
    #[test_case(WolfMethod::TlsServerV1_2)]
    #[test_case(WolfMethod::TlsServerV1_3)]
    fn wolfssl_context_new(method: WolfMethod) {
        wolf_init().unwrap();
        let _ = method.into_method_ptr().unwrap();
        wolf_cleanup().unwrap();
    }

    #[test]
    fn wolf_context_new() {
        WolfContextBuilder::new(WolfMethod::DtlsClient).unwrap();
        wolf_cleanup().unwrap();
    }

    #[test]
    fn wolf_context_root_certificate_buffer() {
        const CA_CERT: &[u8] = &include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_data/ca_cert_der_2048"
        ));

        let cert = RootCertificate::Asn1Buffer(CA_CERT);

        let _ = WolfContextBuilder::new(WolfMethod::TlsClient)
            .unwrap()
            .with_root_certificate(cert)
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn wolf_context_set_cipher_list() {
        let _ = WolfContextBuilder::new(WolfMethod::DtlsClient)
            .unwrap()
            // This string might need to change depending on the flags
            // we built wolfssl with.
            .with_cipher_list("TLS13-CHACHA20-POLY1305-SHA256")
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn wolf_context_set_certificate_buffer() {
        const SERVER_CERT: &[u8] = &include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_data/server_cert_der_2048"
        ));

        let cert = Secret::Asn1Buffer(SERVER_CERT);

        let _ = WolfContextBuilder::new(WolfMethod::TlsClient)
            .unwrap()
            .with_certificate(cert)
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn wolf_context_set_private_key_buffer() {
        const SERVER_KEY: &[u8] = &include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_data/server_key_der_2048"
        ));

        let key = Secret::Asn1Buffer(SERVER_KEY);

        let _ = WolfContextBuilder::new(WolfMethod::TlsClient)
            .unwrap()
            .with_private_key(key)
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn wolf_context_set_secure_renegotiation() {
        let _ = WolfContextBuilder::new(WolfMethod::TlsClient)
            .unwrap()
            .with_secure_renegotiation()
            .unwrap();

        wolf_cleanup().unwrap();
    }
}
