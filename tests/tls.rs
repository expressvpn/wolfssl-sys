//! A quick-and-dirty integration test that combines both
//! [`server-tls.c`][s] and [`client-tls.c`][c] from the
//! [`wolfssl-examples`][e] repository. This also serves as a good way
//! to establish a vertical slice.
//!
//! This relies on keys/certs also found in the repository,
//! [`ca-cert.pem`][x], [`server-cert.pem`][y], and
//! [`server-key.pem`][z].
//!
//! [e]: https://github.com/wolfSSL/wolfssl-examples
//! [s]: https://github.com/wolfSSL/wolfssl-examples/blob/b1d05ac08dfb92b806e8e86f055b8e95e4b11852/tls/server-tls.c
//! [c]: https://github.com/wolfSSL/wolfssl-examples/blob/b1d05ac08dfb92b806e8e86f055b8e95e4b11852/tls/client-tls.c
//! [x]: https://github.com/wolfSSL/wolfssl-examples/blob/b1d05ac08dfb92b806e8e86f055b8e95e4b11852/certs/ca-cert.pem
//! [y]: https://github.com/wolfSSL/wolfssl-examples/blob/b1d05ac08dfb92b806e8e86f055b8e95e4b11852/certs/server-cert.pem
//! [z]: https://github.com/wolfSSL/wolfssl-examples/blob/b1d05ac08dfb92b806e8e86f055b8e95e4b11852/certs/server-key.pem

use wolfssl_sys;

const CA_CERT_PEM: &str = include_str!("ca-cert.pem");
const SERVER_CERT_PEM: &str = include_str!("server-cert.pem");
const SERVER_KEY_PEM: &str = include_str!("server-key.pem");
