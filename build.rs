/*!
 * Contains the build process for WolfSSL
 */

extern crate bindgen;

use autotools::Config;
use std::collections::HashSet;
use std::env;
use std::path::PathBuf;
use std::process::Command;

static WOLFSSL_VERSION: &str = "wolfssl-5.4.0-stable";

/**
 * Work around for bindgen creating duplicate values.
 */
#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl bindgen::callbacks::ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        if self.0.contains(name) {
            bindgen::callbacks::MacroParsingBehavior::Ignore
        } else {
            bindgen::callbacks::MacroParsingBehavior::Default
        }
    }
}

/**
 * Extract WolfSSL
 */
fn extract_wolfssl(dest: &str) -> std::io::Result<()> {
    Command::new("tar")
        .arg("-zxvf")
        .arg(format!("vendor/{}.tar.gz", WOLFSSL_VERSION))
        .arg("-C")
        .arg(dest)
        .status()
        .unwrap();

    Ok(())
}

/**
Builds WolfSSL
*/
fn build_wolfssl(dest: &str) -> PathBuf {
    // Create the config
    let mut conf = Config::new(format!("{}/{}", dest, WOLFSSL_VERSION));
    // Configure it
    conf.reconf("-ivf")
        // Only build the static library
        .enable_static()
        .disable_shared()
        // Enable TLS/1.3
        .enable("tls13", None)
        // Disable old TLS versions
        .disable("oldtls", None)
        // Enable single threaded mode
        .enable("singlethreaded", None)
        // Enable D/TLS
        .enable("dtls", None)
        // Enable single precision
        .enable("sp", None)
        // Enable single precision ASM
        .enable("sp-asm", None)
        // Enable setting the D/TLS MTU size
        .enable("dtls-mtu", None)
        // Disable SHA3
        .disable("sha3", None)
        // Disable DH key exchanges
        .disable("dh", None)
        // Enable elliptic curve exchanges
        .enable("curve25519", None)
        // Enable Secure Renegotiation
        .enable("secure-renegotiation", None)
        // CFLAGS
        .cflag("-g")
        .cflag("-fPIC")
        .cflag("-DWOLFSSL_DTLS_ALLOW_FUTURE")
        .cflag("-DWOLFSSL_MIN_RSA_BITS=2048")
        .cflag("-DWOLFSSL_MIN_ECC_BITS=256");

    if build_target::target_arch().unwrap() == build_target::Arch::X86_64 {
        // Enable Intel ASM optmisations
        conf.enable("intelasm", None);
        // Enable AES hardware acceleration
        conf.enable("aesni", None);
    }

    if build_target::target_arch().unwrap() == build_target::Arch::AARCH64 {
        // Enable ARM ASM optimisations
        conf.enable("armasm", None);
    }

    if build_target::target_arch().unwrap() == build_target::Arch::ARM {
        // Enable ARM ASM optimisations
        conf.enable("armasm", None);
    }

    // Build and return the config
    conf.build()
}

fn main() -> std::io::Result<()> {
    // Get the build directory
    let dst_string = env::var("OUT_DIR").unwrap();

    // Extract WolfSSL
    extract_wolfssl(&dst_string)?;
    // Configure and build WolfSSL
    let dst = build_wolfssl(&dst_string);

    // We want to block some macros as they are incorrectly creating duplicate values
    let ignored_macros = IgnoreMacros(vec!["IPPORT_RESERVED".into()].into_iter().collect());

    // Build the Rust binding
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}/include/", dst_string))
        .parse_callbacks(Box::new(ignored_macros))
        .rustfmt_bindings(true)
        .blocklist_file("/usr/include/stdlib.h")
        .generate()
        .expect("Unable to generate bindings");

    // Write out the bindings
    bindings
        .write_to_file(dst.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // Tell cargo to tell rustc to link in WolfSSL
    println!("cargo:rustc-link-lib=static=wolfssl");
    println!(
        "cargo:rustc-link-search=native={}",
        format!("{}/lib/", dst_string)
    );
    println!("cargo:include={}", dst_string);

    // Invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // That should do it...
    Ok(())
}
