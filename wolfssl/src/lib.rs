use wolfssl_sys::raw_bindings;

/// Return error values for [`wolf_init`]
#[derive(Debug)]
pub enum WolfInitError {
    /// Corresponds with `BAD_MUTEX_E`
    Mutex,
    /// Corresponds with `WC_INIT_E`
    WolfCrypt,
}

/// Wraps [`wolfSSL_Init`][0]
///
/// Note that this is also internally during initialization by
/// [`WolfSslContext`].
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

/// Return error values for [`wolf_cleanup`]
#[derive(Debug)]
pub enum WolfCleanupError {
    /// Corresponds with `BAD_MUTEX_E`
    Mutex,
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
}
