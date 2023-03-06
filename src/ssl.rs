use crate::raw_bindings::{wolfSSL_Cleanup, wolfSSL_Init, BAD_MUTEX_E, WC_INIT_E, WOLFSSL_SUCCESS};

/// Return error values for [`init`]
#[derive(Debug)]
pub enum InitError {
    Mutex,
    WolfCrypt,
}

/// Wraps [`wolfSSL_Init`][0]
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

#[cfg(test)]
mod tests {
    use super::*;

    // simple test to verify that the two functions work
    #[test]
    fn init_cleanup() {
        init().unwrap();
        cleanup().unwrap();
    }
}
