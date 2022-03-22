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
wolfssl-sys = "0.1.0"
```
To ensure that the crate can be built even offline, the crate includes the source code for WolfSSL (currently version `5.2.0`). WolfSSL uses autotools to build and configure the library so this will need to be install on the build system.

## Building with Earthly
There is also an `Earthfile` provided so that you can build the crate in [Earthly](https://earthly.dev):

```
earthly +build-crate
```

## TODO

* Resolve the warnings in the auto generated tests
* Add feature support to allow customisation of the WolfSSL build
