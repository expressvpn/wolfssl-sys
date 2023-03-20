use wolfssl_sys::raw_bindings;

/// Return error values for [`wolf_init`]
#[derive(Debug)]
pub enum WolfInitError {
    /// Corresponds with `BAD_MUTEX_E`
    Mutex,
    /// Corresponds with `WC_INIT_E`
    WolfCrypt,
}

/// Return error values for [`wolf_cleanup`]
#[derive(Debug)]
pub enum WolfCleanupError {
    /// Corresponds with `BAD_MUTEX_E`
    Mutex,
}

/// Possible errors returnable by
/// [`wolfSSL_CTX_load_verify_buffer`][0] and [`wolfSSL_CTX_load_verify_locations`][1]
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_buffer
/// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_locations
#[derive(Debug)]
pub enum LoadRootCertificateError {
    /// `SSL_FAILURE`
    Failure,
    /// `SSL_BAD_FILETYPE`
    BadFiletype,
    /// `SSL_BAD_FILE`
    BadFile,
    /// `MEMORY_E`
    Memory,
    /// `ASN_INPUT_E`
    AsnInput,
    /// `ASN_BEFORE_DATE_E`
    AsnBeforeDate,
    /// `ASN_AFTER_DATE_E`
    AsnAfterDate,
    /// `BUFFER_E`
    Buffer,
    /// `BAD_PATH_ERROR`
    Path,
    /// Error values outside of what was documented
    Other(i64),
}

impl From<i32> for LoadRootCertificateError {
    fn from(value: std::os::raw::c_int) -> Self {
        match value {
            raw_bindings::WOLFSSL_BAD_FILETYPE => Self::BadFiletype,
            raw_bindings::WOLFSSL_BAD_FILE => Self::BadFile,
            raw_bindings::MEMORY_E => Self::Memory,
            raw_bindings::ASN_INPUT_E => Self::AsnInput,
            raw_bindings::BUFFER_E => Self::Buffer,
            raw_bindings::WOLFSSL_FAILURE => Self::Failure,
            raw_bindings::ASN_AFTER_DATE_E => Self::AsnAfterDate,
            raw_bindings::ASN_BEFORE_DATE_E => Self::AsnBeforeDate,
            raw_bindings::BAD_PATH_ERROR => Self::Path,
            e => Self::Other(e as i64), // e => panic!("Undocumented return value: got {e}"),
        }
    }
}
