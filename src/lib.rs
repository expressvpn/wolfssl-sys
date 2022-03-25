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
            println!("Res: {:?}", res);

            if res == WOLFSSL_SUCCESS {
                println!("OK!");
            }
        }
    }
}
