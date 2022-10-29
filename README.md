# wolfssl-sys
This crate provides auto-generated unsafe Rust bindings through [bindgen](https://github.com/rust-lang/rust-bindgen/), to C functions provided by the WolfSSL library. Currently the build options are hard coded to match what we use for Lightway, but will be updated soon to support features.

*Note*: This is a very early release and as such there are a number of limitations with this implementation. Expect it to improve significantly in the very near future.

## Why WolfSSL?
At [ExpressVPN](https://www.expressvpn.com) we love [WolfSSL](https://www.wolfssl.com). It's fast, secure, easy to use and of course it's Open Source. That's why when we were looking at TLS libraries to use as the core of [Lightway](https://www.lightway.com), WolfSSL was a clear winner. Now that we're doing more research with Rust, it's only natural that we'd want to keep using WolfSSL, but alas, there weren't any Rust bindings available.

So we built one :)


## Getting started
Add `wolfssl-sys` to your Cargo manifest:

```
[dependencies]
wolfssl-sys = "0.1.12"
```
To ensure that the crate can be built even offline, the crate includes the source code for WolfSSL (currently version `5.5.2`). WolfSSL uses autotools to build and configure the library so this will need to be installed on the build system.

Note: This crate includes a patch from the WolfSSL master branch to improve reporting with Post Quantum curves. It has no other effect and as it is already merged into master, will be removed when WolfSSL cuts a new release.

## Building with Earthly
There is also an `Earthfile` provided so that you can build the crate in [Earthly](https://earthly.dev):

```
earthly +build-crate
```

## Post Quantum cryptography support
WolfSSL offers Post Quantum support by leveraging `liboqs`, a library from the [Open Quantum Safe project](https://openquantumsafe.org/). This includes the current hybrid schemes which are the recommended way of experimenting with Post Quantum today. The feature is not enabled by default as it requires building and linking against `liboqs` which would increase the library size and increase compile time. It can be enabled by enabling the `postquantum` feature:

``` toml
[dependencies]
wolfssl-sys = { version = "0.1.12" features = ["postquantum"] }
```

This will automatically build `liboqs` from the `oqs-sys` crate and link WolfSSL against it, making definitions such as `WOLFSSL_P521_KYBER_LEVEL5` available.

### Testing it
The crate includes an example called `connect_pq`. It is a *very* basic application that connects to the test site of the Open Quantum Safe project and tries to use the hybrid P521 and Kyber Level 5 key exchange mechanism. You can run this example with:

``` shell
cargo run --example connect_pq --features=postquantum
```

All being well you should get output like this:

``` text
Connected to  test.openquantumsafe.org
Key Exchange: "P521_KYBER_LEVEL5"
Cipher:       "TLS13-AES128-GCM-SHA256"
```

The example shows how easy it is to use WolfSSL's Post Quantum support, but it is certainly not production ready!



## Contributors
A number of people have taken the time to contribute towards this crate. From opening valuable issues, to contributing a line or two of code, we would like to give credit for their help here:


## TODO

* Resolve the warnings in the auto generated tests
* Add feature support to allow customisation of the WolfSSL build
