VERSION 0.6
FROM rust:1.67.1

WORKDIR /wolfssl-sys

build-deps:
    RUN apt-get update -qqy
    RUN apt-get install -qqy autoconf autotools-dev libtool-bin clang cmake
    RUN rustup component add rustfmt

copy-src:
    FROM +build-deps
    COPY Cargo.toml wrapper.h build.rs ./
    COPY --dir src ./
    COPY --dir vendor ./
    COPY --dir examples ./

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
