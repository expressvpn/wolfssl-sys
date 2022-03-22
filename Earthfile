VERSION 0.6
FROM rust:1.59

WORKDIR /wolfssl-sys

build-deps:
    RUN apt-get update -qqy
    RUN apt-get install -qqy autoconf autotools-dev libtool-bin clang

copy-src:
    FROM +build-deps
    COPY Cargo.toml wrapper.h build.rs ./
    COPY --dir src ./
    COPY --dir vendor ./

build-dev:
    FROM +copy-src
    RUN cargo build
    SAVE ARTIFACT target/debug /release/ AS LOCAL artifacts/debug/

build-release:
    FROM +copy-src
    RUN cargo build --release
    SAVE ARTIFACT target/release /release/ AS LOCAL artifacts/release/

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
