use crate::raw_bindings::{wolfSSL_Cleanup, wolfSSL_Init, BAD_MUTEX_E, WC_INIT_E, WOLFSSL_SUCCESS};
use super::raw_bindings::{
    wolfDTLS_client_method, wolfDTLS_server_method, wolfDTLSv1_2_client_method,
    wolfDTLSv1_2_server_method, wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
    wolfSSLv23_client_method, wolfSSLv23_server_method, wolfTLS_client_method,
    wolfTLS_server_method, wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
    wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
};
use super::raw_bindings::{wolfSSL_CTX_free, wolfSSL_CTX_new};
use super::raw_bindings::{wolfSSL_free, wolfSSL_new};
use super::raw_bindings::{WOLFSSL_CTX, WOLFSSL_METHOD, WOLFSSL};


/// Return error values for [`init`]
#[derive(Debug)]
pub enum InitError {
    Mutex,
    WolfCrypt,
}

/// Wraps [`wolfSSL_Init`][0]
///
/// Note that this is also internally during initialization by
/// [`WolfSslContext`].
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_init
pub fn init() -> Result<(), InitError> {
    match unsafe { wolfSSL_Init() } {
        WOLFSSL_SUCCESS => Ok(()),
        BAD_MUTEX_E => Err(InitError::Mutex),
        WC_INIT_E => Err(InitError::WolfCrypt),
        e => panic!("Unexpected return value from `wolfSSL_Init`. Got {e}"),
    }
}

/// Return error values for [`cleanup`]
#[derive(Debug)]
pub enum CleanupError {
    Mutex,
}

/// Wraps [`wolfSSL_Cleanup`][0]
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_cleanup
pub fn cleanup() -> Result<(), CleanupError> {
    match unsafe { wolfSSL_Cleanup() } {
        WOLFSSL_SUCCESS => Ok(()),
        BAD_MUTEX_E => Err(CleanupError::Mutex),
        e => panic!("Unexpected return value from `wolfSSL_Cleanup. Got {e}`"),
    }
}

// We support these for now. The methods here correspond directly to
// the build flags we currently set in `build.rs`
pub enum WolfSslMethod {
    DtlsClient,
    DtlsClientV1_2,
    DtlsClientV1_3,
    DtlsServer,
    DtlsServerV1_2,
    DtlsServerV1_3,
    SslClientV23,
    SslServerV23,
    TlsClient,
    TlsClientV1_2,
    TlsClientV1_3,
    TlsServer,
    TlsServerV1_2,
    TlsServerV1_3,
}

impl WolfSslMethod {
    pub fn into_method_ptr(self) -> Option<*mut WOLFSSL_METHOD> {
        let ptr = match self {
            Self::DtlsClient => unsafe { wolfDTLS_client_method() },
            Self::DtlsClientV1_2 => unsafe { wolfDTLSv1_2_client_method() },
            Self::DtlsClientV1_3 => unsafe { wolfDTLSv1_3_client_method() },
            Self::DtlsServer => unsafe { wolfDTLS_server_method() },
            Self::DtlsServerV1_2 => unsafe { wolfDTLSv1_2_server_method() },
            Self::DtlsServerV1_3 => unsafe { wolfDTLSv1_3_server_method() },
            Self::SslClientV23 => unsafe { wolfSSLv23_client_method() },
            Self::SslServerV23 => unsafe { wolfSSLv23_server_method() },
            Self::TlsClient => unsafe { wolfTLS_client_method() },
            Self::TlsClientV1_2 => unsafe { wolfTLSv1_2_client_method() },
            Self::TlsClientV1_3 => unsafe { wolfTLSv1_3_client_method() },
            Self::TlsServer => unsafe { wolfTLS_server_method() },
            Self::TlsServerV1_2 => unsafe { wolfTLSv1_2_server_method() },
            Self::TlsServerV1_3 => unsafe { wolfTLSv1_3_server_method() },
        };

        if !ptr.is_null() {
            Some(ptr)
        } else {
            None
        }
    }
}

pub struct WolfSslContext(*mut WOLFSSL_CTX);

impl WolfSslContext {
    #[allow(dead_code)]
    pub fn new(method: WolfSslMethod) -> Option<Self> {
        let method_fn = method.into_method_ptr()?;

        let ctx = unsafe { wolfSSL_CTX_new(method_fn) };

        if !ctx.is_null() {
            Some(Self(ctx))
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn create_session(&self) -> Option<WolfSslSession> {
        let ptr = unsafe { wolfSSL_new(self.0) };
        if !ptr.is_null() {
            Some(WolfSslSession(ptr))
        } else {
            None
        }
    }
}

impl Drop for WolfSslContext {
    fn drop(&mut self) {
        unsafe { wolfSSL_CTX_free(self.0) }
    }
}

pub struct WolfSslSession(*mut WOLFSSL);

impl Drop for WolfSslSession {
    fn drop(&mut self) {
        unsafe { wolfSSL_free(self.0) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    // simple test to verify that the two functions work
    #[test]
    fn init_cleanup() {
        init().unwrap();
        cleanup().unwrap();
    }

    #[test]
    fn context_create_session() {
        let ctx = WolfSslContext::new(WolfSslMethod::DtlsClient).unwrap();
        ctx.create_session().unwrap();
    }

    #[test_case(WolfSslMethod::DtlsClient)]
    #[test_case(WolfSslMethod::DtlsClientV1_2)]
    #[test_case(WolfSslMethod::DtlsClientV1_3)]
    #[test_case(WolfSslMethod::DtlsServer)]
    #[test_case(WolfSslMethod::DtlsServerV1_2)]
    #[test_case(WolfSslMethod::DtlsServerV1_3)]
    #[test_case(WolfSslMethod::SslClientV23)]
    #[test_case(WolfSslMethod::SslServerV23)]
    #[test_case(WolfSslMethod::TlsClient)]
    #[test_case(WolfSslMethod::TlsClientV1_2)]
    #[test_case(WolfSslMethod::TlsClientV1_3)]
    #[test_case(WolfSslMethod::TlsServer)]
    #[test_case(WolfSslMethod::TlsServerV1_2)]
    #[test_case(WolfSslMethod::TlsServerV1_3)]
    fn wolfssl_context_new(method: WolfSslMethod) {
        WolfSslContext::new(method).unwrap();
    }
}
