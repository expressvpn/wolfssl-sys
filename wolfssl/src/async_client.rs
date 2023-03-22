//! This module attempts to implement `AsyncRead` and `AsyncWrite` for
//! `WolfSession`.
//!
//! WolfSSL has 2 ways of registering an input/output facility for the
//! SSL connection:
//! 1. File descriptors, via [`wolfSSL_set_fd`][0].
//!    - This seems feasible with tokio since at least
//!      [`TcpStream`][5] allows direct access of the raw file
//!      descriptor
//! 2. Custom IO callbacks, via a workflow enabled by an assortment of
//!    functions that operate roughly like this:
//!    - Register a callback at the `WOLFSSL_CTX` (context) level via
//!      [`wolfSSL_CTX_SetIORecv`][1] and/or
//!      `wolfSSL_CTX_SetIOSend` (online docs not found, unfortunately).
//!    - Register a `void* ctx` object on the `WOLFSSL` (session) level
//!      via [`wolfSSL_SetIOWriteCtx`][2] and/or
//!      `wolfSSL_SetIOReadCtx`.
//!    - Whenever a `WOLFSSL` ptr calls [`wolfSSL_read`][3] or
//!      [`wolfSSL_write`][4] the context-level callbacks get
//!      invoked with session-level `void* ctx` payloads.
//!
//! However, we're going to implement option #2 anyway, since we might
//! eventually need to adapt the tun driver.
//!
//! [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_set_fd
//! [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_ctx_setiorecv
//! [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_setioreadctx
//! [3]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_read
//! [4]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_write
//! [5]: https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html#impl-AsRawFd-for-TcpStream

use crate::{WolfContext, WolfContextBuilder, WolfSession};
use wolfssl_sys::raw_bindings;

use bytes::{Buf, BytesMut};
use parking_lot::Mutex;
use std::{
    io::Result as IoResult,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Record size is defined as `2^14 + 1`.
///
/// > ...the full encoded TLSInnerPlaintext MUST NOT exceed 2^14 + 1
/// > octets
/// [source][0]
///
/// This value must also equal or exceed `<wolfssl/internal.h>`'s
/// `MAX_RECORD_SIZE` (though I'm not sure how to assert that yet).
///
/// [0]: https://www.rfc-editor.org/rfc/rfc8446#section-5.4
const TLS_MAX_RECORD_SIZE: usize = 2usize.pow(14) + 1;

/// The struct that will be passed into the `ctx` variable (as a
/// `void*`) of the wolfssl ctx callbacks.
struct WolfClientCallbackContext {
    /// To be read into callback buffer
    read_buffer: BytesMut,
    /// to be written from the callback buffer
    write_buffer: BytesMut,
    // TODO (pangt): figure out if this is still necessary
    real_frame_size: usize,
}

// Lets do 1:1 context/session for now, and punt the design complexity
// of having to manage different contexts to later.
struct WolfClient<T: AsyncRead + AsyncWrite + Unpin> {
    // NOTE (pangt): contexts carry process-level defaults and this is
    // actually bad design: We should somehow carry a reference of the
    // context around instead
    ssl_context: WolfContext,
    ssl_session: Mutex<WolfSession>,
    session_context: WolfClientCallbackContext,
    stream: T,
}
impl<T: AsyncRead + AsyncWrite + Unpin> WolfClient<T> {
    /// Takes in a context and registers additional callbacks that
    /// allows for asynchronous IO.
    pub fn with_context_and_stream(builder: WolfContextBuilder, stream: T) -> Result<Self, ()> {
        let ssl_context = builder.build();

        // register context-side callbacks
        unsafe {
            raw_bindings::wolfSSL_CTX_SetIORecv(ssl_context.0, Some(wolf_tls_read_cb));
            raw_bindings::wolfSSL_CTX_SetIOSend(ssl_context.0, Some(wolf_tls_write_cb));
        }

        // Create a new SSL session
        let ssl_session = ssl_context.new_session().ok_or(());

        // Register session-side callbacks

        // Self {
        //     ssl_context,
        //     stream,
        //     ssl_session:
        // }

        todo!("Fill in the blanks")
    }
}

/// The custom IO callback documented at [`EmbedRecieve`][0] (whose
/// inputs and outputs we need to emulate).
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-embedreceive
extern "C" fn wolf_tls_read_cb(
    _ssl: *mut raw_bindings::WOLFSSL,
    buf: *mut ::std::os::raw::c_char,
    sz: ::std::os::raw::c_int,
    ctx: *mut ::std::os::raw::c_void,
) -> ::std::os::raw::c_int {
    todo!();

    // Recover our context
    let data = unsafe { &mut *(ctx as *mut WolfClientCallbackContext) };

    // Grab our read buffer
    let mut read_buffer = &mut data.read_buffer;
    // If the buffer is empty, there's nothinng more to do here.
    // Tell WolfSSL that we need more data
    if read_buffer.is_empty() {
        return wolfssl_sys::raw_bindings::IOerrors_WOLFSSL_CBIO_ERR_WANT_READ;
    }

    // Find out how much we should or can copy to WolfSSL.
    // WolfSSL asks for data piecemeal, so often it will ask
    // for just 2 or 5 bytes at a time. Passing more will cause
    // it to error. On the other hand though, it might need a
    // 1000 bytes, but all we have is 500 - in which case just
    // send all that we can.
    let num_of_bytes = if read_buffer.len() > sz as usize {
        // Copy the amount WolfSSL wants
        sz as usize
    } else {
        // Copy in all that we can
        read_buffer.len()
    };

    // Now for some slight of hand - make the buffer provided by WolfSSL
    // appear as a slice. Despite this being an unsafe piece of code,
    // it will make further interactions far safer by conceptualising
    // the buffer pointer nad length together.
    //
    // We use `num_of_bytes` here to ensure that we are always dealing with
    // valid memory
    let wolf_read_buffer =
        unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, num_of_bytes as usize) };

    // Copy the data into WolfSSL's buffer
    wolf_read_buffer.copy_from_slice(&read_buffer[..num_of_bytes]);

    // Advance the buffer to remove the data we just consumed
    Buf::advance(&mut read_buffer, num_of_bytes);

    // Return the count to WolfSSL
    num_of_bytes as ::std::os::raw::c_int
}

/// The custom IO callback documented at [`EmbedSend`][0] (whose
/// inputs and outputs we need to emulate).
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-embedsend
extern "C" fn wolf_tls_write_cb(
    _ssl: *mut raw_bindings::WOLFSSL,
    buf: *mut ::std::os::raw::c_char,
    sz: ::std::os::raw::c_int,
    ctx: *mut ::std::os::raw::c_void,
) -> ::std::os::raw::c_int {
    todo!();

    // // Recover our context
    // let data = unsafe { &mut *(ctx as *mut WolfClientCallbackContext) };

    // // Extract our write buffer
    // let write_buffer = &mut data.write_buffer;

    // // Create a slice using the c pointer and length from WolfSSL. This
    // // contains the bytes we need to write out
    // let slice = unsafe { slice::from_raw_parts(buf as *const u8, sz as usize) };

    // // Copy bytes into our write buffer.
    // // Our buffer will resize as needed
    // // TODO: Set the buffer to be the max size that Wolf uses
    // //       will save any reallocation costs (it should be ~16KB)
    // write_buffer.extend_from_slice(slice);

    // // Return the number of bytes WolfSSL gave us as we can
    // // consume all of them. At this point however WolfSSL believes
    // // that the send was successful, it has no way to know otherwise
    // sz
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for WolfClient<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        // Pull out our TCPClient
        let inner = Pin::into_inner(self);
        // Pin the stream
        let pinned_tcpstream = Pin::new(&mut inner.stream);

        // Build a read buffer
        let mut poll_read_buffer = vec![0u8; TLS_MAX_RECORD_SIZE];

        let remaining = std::cmp::min(poll_read_buffer.len(), buf.remaining());
        let mut buffer = ReadBuf::new(&mut poll_read_buffer[..remaining]);

        // Read from the inner stream
        match pinned_tcpstream.poll_read(cx, &mut buffer) {
            Poll::Ready(Ok(())) => (),
            x => {
                // Anything other than Ok, and we just pass it through
                // to the wrapping stream.
                //println!("Returned: {:#?}", x);
                return x;
            }
        }

        // Extend our read buffer (the one we pass to WolfSSL) with
        // the freshly read data
        // &mut inner
        inner
            .session_context
            .read_buffer
            .extend_from_slice(&buffer.filled());

        // Reset the read buffer
        buffer.clear();

        // Populate buffer from `pinned_tcpstream` -> `context_read_buffer`
        // --------------------------------------
        // Pull data from `wolfSSL_read` -> `buffer` -> `buf`

        // Keep calling wolfSSL_read until we've processed all the data
        // TODO This doesn't handle conditions nicely - need to fix this!
        loop {
            let ssl = inner.ssl_session.lock();
            let res = unsafe {
                raw_bindings::wolfSSL_read(
                    ssl.0,
                    &mut buffer.initialize_unfilled()[..] as *mut _ as *mut ::std::os::raw::c_void,
                    buffer.remaining() as i32,
                )
            };

            if res <= 0 {
                break;
            } else {
                buffer.advance(res as usize);
            }
        }

        // Copy into upstream's buffer - but only as much as it can take
        buf.put_slice(&buffer.filled());

        // Read completed okay
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WolfClient<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        // Unpin ourselves
        let inner = Pin::into_inner(self);

        // Grab WolfSSL's write buffer
        let write_buffer = &mut inner.session_context.write_buffer;

        // If we still have data from last time, bypass WolfSSL
        // and try to drain the buffer
        if write_buffer.is_empty() {
            inner.session_context.real_frame_size = buf.len();

            //Grab mutex
            let ssl = inner.ssl_session.lock();

            // Cast buf to a c void pointer to hand over to WolfSSL
            let buf_ptr: *const ::std::os::raw::c_void =
                buf as *const _ as *const ::std::os::raw::c_void;

            // Encrypt the buffer
            let res = unsafe { raw_bindings::wolfSSL_write(ssl.0, buf_ptr, buf.len() as i32) };
        }

        // Create a temporary buffer
        let mut sigh = BytesMut::with_capacity(TLS_MAX_RECORD_SIZE);

        // Append the encrypted data to our temp buffer
        sigh.extend_from_slice(&write_buffer);

        // Clear the buffer once written
        //write_buffer.truncate(0);

        // Pin the stream to stop it running away
        let pinned = Pin::new(&mut inner.stream);

        // Try to send to the stream
        match pinned.poll_write(cx, &sigh) {
            Poll::Ready(Ok(n)) => {
                // Did we write all of the frame out?
                if n == write_buffer.len() {
                    let write_buffer_len = write_buffer.len();
                    // Truncate the buffer
                    write_buffer.truncate(0);

                    let real_size = _inner.our_context.real_frame_size;
                    // Remove the real frame size
                    _inner.our_context.real_frame_size = 0;
                    // All written, we can tell upstream the frame
                    // was sent
                    if real_size == 0 {
                        println!("Tried to write zero from a full write! Buf len was: {} while write_buffer len was: {}", buf.len(),write_buffer_len);
                    }
                    return Poll::Ready(Ok(real_size));
                }

                // This is where it gets messy...
                // We have written some bytes, but not all of them
                // This makes it hard to tell upstream what we sent
                // as it won't be directly related to the bytes it
                // gave us to write as we write encrypted bytes.
                //
                // The idea is to tell upstream that we are pending
                // which should make it try again later with the same bytes
                // given us a chance to flush the rest of our buffer. Hopefully
                // this will actually trigger a read from the socket still but...

                /*
                println!(
                    "Wanted to write {} but wrote {} of a faked {}. It was a fresh packet? {}",
                    write_buffer.len(),
                    n,
                    buf.len(),
                    // switch
                );
                */
                // Update the write buffer so we only have the unsent data
                Buf::advance(write_buffer, n);
                _inner.our_context.real_frame_size -= 1;
                // Lie to upstream that we couldn't send anything
                return Poll::Ready(Ok(1));
            }
            x => {
                //println!("Returned: {:#?}", x);
                x
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        todo!()
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        todo!()
    }
}
