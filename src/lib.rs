// C doesn't follow rust rules for naming
// so we don't want to warn here
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
// To work around an issue in bindgen (#1651)
#![allow(deref_nullptr)]

// Pull in the bindings file created during the initial build
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/**
 * Add more tests to gain more confidence in the bindings
 */
#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn init_wolfssl() {
        unsafe {
            let res = wolfSSL_Init();
            assert_eq!(res, WOLFSSL_SUCCESS);
        }
    }

    #[test]
    #[cfg(feature = "postquantum")]
    fn test_post_quantum_available() {
        unsafe {
            // Init WolfSSL
            let res = wolfSSL_Init();

            // Set up client method
            let method = wolfTLSv1_3_client_method();

            // Create context
            let context = wolfSSL_CTX_new(method);

            // Create new SSL stream
            let ssl = wolfSSL_new(context);

            // Enable Kyber
            let res = wolfSSL_UseKeyShare(ssl, WOLFSSL_P521_KYBER_LEVEL5.try_into().unwrap());

            // Check that Kyber was enabled
            assert_eq!(res, WOLFSSL_SUCCESS);
        }
    }
}
