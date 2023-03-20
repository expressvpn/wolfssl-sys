VERSION 0.6
FROM rust:1.68.0

WORKDIR /wolfssl-sys

build-deps:
    RUN apt-get update -qqy
    RUN apt-get install -qqy autoconf autotools-dev libtool-bin clang cmake
    RUN rustup component add rustfmt

copy-wolfssl-sys:
    FROM +build-deps
    COPY --dir               \
        wolfssl-sys/src      \
        wolfssl-sys/vendor   \
        wolfssl-sys/examples \
        ./wolfssl-sys
    COPY wolfssl-sys/Cargo.toml wolfssl-sys/wrapper.h wolfssl-sys/build.rs ./wolfssl-sys

copy-src:
    FROM +build-deps
    FROM +copy-wolfssl-sys
    COPY Cargo.toml Cargo.lock ./

build-dev:
    FROM +copy-src
    RUN cargo build
    SAVE ARTIFACT target/debug /debug AS LOCAL artifacts/debug

build-release:
    FROM +copy-src
    RUN cargo build --release
    SAVE ARTIFACT target/release /release AS LOCAL artifacts/release

run-tests:
    FROM +copy-src
    RUN cargo test

build:
    BUILD +run-tests
    BUILD +build-release

build-crate:
    FROM +copy-src
    RUN cargo package
    SAVE ARTIFACT target/package/*.crate /package/ AS LOCAL artifacts/crate/

lint:
    FROM +copy-src
    RUN rustup component add clippy
    RUN cargo clippy --all-features --all-targets -- -D warnings
