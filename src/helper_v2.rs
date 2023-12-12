//! Stream wrapper to calculate hmac.
//! All structs in this file is used by V2 protocol only.

use std::{
    cell::RefCell,
    future::Future,
    io::Read,
    marker::PhantomData,
    pin::Pin,
    ptr::copy_nonoverlapping,
    rc::Rc,
    task::{Context, Poll},
};

use hmac::Mac;
use monoio::{
    buf::{IoBuf, IoBufMut, IoVecWrapper, IoVecWrapperMut},
    io::{
        as_fd::{AsReadFd, AsWriteFd},
        AsyncReadRent, AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt,
    },
    BufResult,
};

use crate::util::prelude::*;

pub(crate) const HMAC_SIZE_V2: usize = 8;

pub(crate) trait HashedStream {
    fn hash_stream(&self) -> [u8; 20];
}

pub(crate) struct HashedReadStream<S> {
    raw: S,
    hmac: hmac::Hmac<sha1::Sha1>,
}

// # Safety
// Here we does not make read and write related, so if S is Split, Self is Split.
unsafe impl<S: monoio::io::Split> monoio::io::Split for HashedReadStream<S> {}

impl<S> HashedReadStream<S> {
    pub(crate) fn new(raw: S, password: &[u8]) -> Result<Self, hmac::digest::InvalidLength> {
        Ok(Self {
            raw,
            hmac: hmac::Hmac::new_from_slice(password)?,
        })
    }

    pub(crate) fn into_inner(self) -> S {
        self.raw
    }

    pub(crate) fn hash(&self) -> [u8; 20] {
        self.hmac
            .clone()
            .finalize()
            .into_bytes()
            .as_slice()
            .try_into()
            .expect("unexpected digest length")
    }
}

impl<S> HashedStream for HashedReadStream<S> {
    fn hash_stream(&self) -> [u8; 20] {
        self.hash()
    }
}

pub struct HashedWriteStream<S> {
    raw: S,
    hmac: Rc<RefCell<(bool, hmac::Hmac<sha1::Sha1>)>>,
}

// # Safety
// Here we does not make read and write related, so if S is Split, Self is Split.
unsafe impl<S: monoio::io::Split> monoio::io::Split for HashedWriteStream<S> {}
unsafe impl<S: monoio::io::Split> monoio::io::Split for &mut HashedWriteStream<S> {}

impl<S: AsReadFd> AsReadFd for HashedWriteStream<S> {
    fn as_reader_fd(&mut self) -> &monoio::io::as_fd::SharedFdWrapper {
        self.raw.as_reader_fd()
    }
}

impl<S: AsWriteFd> AsWriteFd for HashedWriteStream<S> {
    fn as_writer_fd(&mut self) -> &monoio::io::as_fd::SharedFdWrapper {
        self.raw.as_writer_fd()
    }
}

impl<S> HashedWriteStream<S> {
    pub(crate) fn new(raw: S, password: &[u8]) -> Result<Self, hmac::digest::InvalidLength> {
        Ok(Self {
            raw,
            hmac: Rc::new(RefCell::new((true, hmac::Hmac::new_from_slice(password)?))),
        })
    }

    pub(crate) fn hash(&self) -> [u8; 20] {
        self.hmac
            .borrow()
            .clone()
            .1
            .finalize()
            .into_bytes()
            .as_slice()
            .try_into()
            .expect("unexpected digest length")
    }

    pub(crate) fn hmac_handler(&self) -> HmacHandler {
        HmacHandler(self.hmac.clone())
    }
}

pub(crate) struct HmacHandler(Rc<RefCell<(bool, hmac::Hmac<sha1::Sha1>)>>);

impl HmacHandler {
    pub(crate) fn hash(&self) -> [u8; 20] {
        self.0
            .borrow()
            .clone()
            .1
            .finalize()
            .into_bytes()
            .as_slice()
            .try_into()
            .expect("unexpected digest length")
    }

    pub(crate) fn disable(&mut self) {
        self.0.borrow_mut().0 = false;
    }
}

impl<S> HashedStream for HashedWriteStream<S> {
    fn hash_stream(&self) -> [u8; 20] {
        self.hash()
    }
}

impl<S: AsyncReadRent> AsyncReadRent for HashedReadStream<S> {
    async fn read<T: monoio::buf::IoBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        let ptr = buf.write_ptr();
        let (result, buf) = self.raw.read(buf).await;
        if let Ok(n) = result {
            // Safety: we can make sure the ptr and n are valid.
            self.hmac
                .update(unsafe { std::slice::from_raw_parts(ptr, n) });
        }
        (result, buf)
    }

    async fn readv<T: monoio::buf::IoVecBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        let slice = match IoVecWrapperMut::new(buf) {
            Ok(slice) => slice,
            Err(buf) => return (Ok(0), buf),
        };

        let (result, slice) = self.read(slice).await;
        buf = slice.into_inner();
        if let Ok(n) = result {
            unsafe { buf.set_init(n) };
        }
        (result, buf)
    }
}

impl<S: AsyncWriteRent> AsyncWriteRent for HashedReadStream<S> {
    fn write<T: monoio::buf::IoBuf>(
        &mut self,
        buf: T,
    ) -> impl Future<Output = BufResult<usize, T>> {
        self.raw.write(buf)
    }

    fn writev<T: monoio::buf::IoVecBuf>(
        &mut self,
        buf_vec: T,
    ) -> impl Future<Output = BufResult<usize, T>> {
        self.raw.writev(buf_vec)
    }

    fn flush(&mut self) -> impl Future<Output = std::io::Result<()>> {
        self.raw.flush()
    }

    fn shutdown(&mut self) -> impl Future<Output = std::io::Result<()>> {
        self.raw.shutdown()
    }
}

impl<S: AsyncReadRent> AsyncReadRent for HashedWriteStream<S> {
    #[inline]
    fn read<T: monoio::buf::IoBufMut>(
        &mut self,
        buf: T,
    ) -> impl Future<Output = BufResult<usize, T>> {
        self.raw.read(buf)
    }

    #[inline]
    fn readv<T: monoio::buf::IoVecBufMut>(
        &mut self,
        buf: T,
    ) -> impl Future<Output = BufResult<usize, T>> {
        self.raw.readv(buf)
    }
}

impl<S: AsyncWriteRent> AsyncWriteRent for HashedWriteStream<S> {
    async fn write<T: monoio::buf::IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        let ptr = buf.read_ptr();
        let (result, buf) = self.raw.write(buf).await;
        if let Ok(n) = result {
            let mut eh = self.hmac.borrow_mut();
            if eh.0 {
                // Safety: we can make sure the ptr and n are valid.
                eh.1.update(unsafe { std::slice::from_raw_parts(ptr, n) });
            }
        }
        (result, buf)
    }

    async fn writev<T: monoio::buf::IoVecBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        let slice = match IoVecWrapper::new(buf) {
            Ok(slice) => slice,
            Err(buf) => return (Ok(0), buf),
        };

        let (result, slice) = self.write(slice).await;
        (result, slice.into_inner())
    }

    fn flush(&mut self) -> impl Future<Output = std::io::Result<()>> {
        self.raw.flush()
    }

    fn shutdown(&mut self) -> impl Future<Output = std::io::Result<()>> {
        self.raw.shutdown()
    }
}

/// Read tls frame and check with tls session.
/// If checking pass, ignore the data.
/// If not, return the data out(and the later data).
/// This wrapper is used to fix a v2 protocol bug:
/// In v2 protocol server may relay application data
/// from handshake server even when client side
/// finished switching. Client must be able to filter
/// out these packets.
pub(crate) struct SessionFilterStream<C, S> {
    session: C,
    stream: S,
    direct: bool,
    direct_buffer: Option<(Vec<u8>, usize)>,
}

impl<C, S> SessionFilterStream<C, S> {
    pub(crate) fn new(session: C, stream: S) -> Self {
        Self {
            session,
            stream,
            direct: false,
            direct_buffer: None,
        }
    }
}

impl<S, C, SD> AsyncReadRent for SessionFilterStream<C, S>
where
    S: AsyncReadRent,
    C: std::ops::DerefMut
        + std::ops::Deref<Target = rustls_fork_shadow_tls::ConnectionCommon<SD>>
        + 'static,
{
    fn read<T: monoio::buf::IoBufMut>(
        &mut self,
        mut buf: T,
    ) -> impl Future<Output = BufResult<usize, T>> {
        const HEADER_BUF_SIZE: usize = 5;

        async move {
            if self.direct {
                return self.stream.read(buf).await;
            }
            if let Some((buffer, copied)) = &mut self.direct_buffer {
                if buffer.len() == *copied {
                    self.direct = true;
                    return self.stream.read(buf).await;
                } else {
                    let cnt = buf.bytes_total().min(buffer.len() - *copied);
                    unsafe {
                        copy_nonoverlapping(buffer.as_ptr().add(*copied), buf.write_ptr(), cnt)
                    };
                    unsafe { buf.set_init(cnt) };
                    *copied += cnt;
                    return (Ok(cnt), buf);
                }
            }
            let slice =
                unsafe { std::slice::from_raw_parts_mut(buf.write_ptr(), buf.bytes_total()) };

            loop {
                match self.session.reader().read(slice) {
                    Ok(n) => {
                        unsafe { buf.set_init(n) };
                        return (Ok(n), buf);
                    }
                    // need more data, read something
                    Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(_) => {
                        self.direct = true;
                        return self.stream.read(buf).await;
                    }
                }

                // read header and body
                let header = vec![0; HEADER_BUF_SIZE];
                let (res, header) = self.stream.read_exact(header).await;
                if res.is_err() {
                    return (res, buf);
                }
                let mut size: [u8; 2] = Default::default();
                size.copy_from_slice(&header[3..5]);
                let data_size = u16::from_be_bytes(size);
                tracing::debug!("session filter read tls frame header, body size is {data_size}");
                let mut data = vec![0; data_size as usize + HEADER_BUF_SIZE];
                unsafe { copy_nonoverlapping(header.as_ptr(), data.as_mut_ptr(), HEADER_BUF_SIZE) };
                let (res, data_slice) = self.stream.read_exact(data.slice_mut(5..)).await;
                if res.is_err() {
                    return (res, buf);
                }
                let data = data_slice.into_inner();
                tracing::debug!("session filter read full tls frame of size {}", data.len());

                let mut cursor = std::io::Cursor::new(&data);
                let _ = self.session.read_tls(&mut cursor);

                if self.session.process_new_packets().is_err() {
                    let cnt = data.len().min(slice.len());
                    unsafe { copy_nonoverlapping(data.as_ptr(), slice.as_mut_ptr(), cnt) };
                    unsafe { buf.set_init(cnt) };
                    self.direct_buffer = Some((data, cnt));
                    return (Ok(cnt), buf);
                }
            }
        }
    }

    async fn readv<T: monoio::buf::IoVecBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        let slice = match IoVecWrapperMut::new(buf) {
            Ok(slice) => slice,
            Err(buf) => return (Ok(0), buf),
        };

        let (result, slice) = self.read(slice).await;
        buf = slice.into_inner();
        if let Ok(n) = result {
            unsafe { buf.set_init(n) };
        }
        (result, buf)
    }
}

pin_project_lite::pin_project! {
    /// ErrGroup works like ErrGroup in golang.
    /// If the two futures all finished with Ok, self is finished with Ok.
    /// If any one of them finished with Err, self is finished with Err.
    pub(crate) struct ErrGroup<FA, FB, A, B, E> {
        #[pin]
        future_a: FA,
        #[pin]
        future_b: FB,
        slot_a: Option<A>,
        slot_b: Option<B>,
        marker: PhantomData<E>,
    }
}

impl<FA, FB, A, B, E> ErrGroup<FA, FB, A, B, E>
where
    FA: Future<Output = Result<A, E>>,
    FB: Future<Output = Result<B, E>>,
{
    pub(crate) fn new(future_a: FA, future_b: FB) -> Self {
        Self {
            future_a,
            future_b,
            slot_a: None,
            slot_b: None,
            marker: Default::default(),
        }
    }
}

impl<FA, FB, A, B, E> Future for ErrGroup<FA, FB, A, B, E>
where
    FA: Future<Output = Result<A, E>>,
    FB: Future<Output = Result<B, E>>,
{
    type Output = Result<(A, B), E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if this.slot_a.is_none() {
            if let Poll::Ready(r) = this.future_a.poll(cx) {
                match r {
                    Ok(a) => *this.slot_a = Some(a),
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
        }
        if this.slot_b.is_none() {
            if let Poll::Ready(r) = this.future_b.poll(cx) {
                match r {
                    Ok(b) => *this.slot_b = Some(b),
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
        }
        if this.slot_a.is_some() && this.slot_b.is_some() {
            return Poll::Ready(Ok((
                this.slot_a.take().unwrap(),
                this.slot_b.take().unwrap(),
            )));
        }
        Poll::Pending
    }
}

pin_project_lite::pin_project! {
    /// FirstRetGroup returns if the first future is ready.
    pub(crate) struct FirstRetGroup<FA, FB, B, E> {
        #[pin]
        future_a: FA,
        #[pin]
        future_b: Option<FB>,
        slot_b: Option<B>,
        marker: PhantomData<E>,
    }
}

pub(crate) enum FutureOrOutput<F, R, E>
where
    F: Future<Output = Result<R, E>>,
{
    Future(F),
    Output(R),
}

impl<FA, FB, A, B, E> FirstRetGroup<FA, FB, B, E>
where
    FA: Future<Output = Result<A, E>>,
    FB: Future<Output = Result<B, E>>,
{
    pub(crate) fn new(future_a: FA, future_b: FB) -> Self {
        Self {
            future_a,
            future_b: Some(future_b),
            slot_b: None,
            marker: Default::default(),
        }
    }
}

impl<FA, FB, A, B, E> Future for FirstRetGroup<FA, FB, B, E>
where
    FA: Future<Output = Result<A, E>>,
    FB: Future<Output = Result<B, E>> + Unpin,
{
    type Output = Result<(A, FutureOrOutput<FB, B, E>), E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if let Poll::Ready(r) = this.future_a.poll(cx) {
            let b = if let Some(output) = this.slot_b.take() {
                FutureOrOutput::Output(output)
            } else {
                FutureOrOutput::Future(this.future_b.get_mut().take().unwrap())
            };
            return Poll::Ready(r.map(|r| (r, b)));
        }
        if this.slot_b.is_none() {
            if let Poll::Ready(r) = this.future_b.as_pin_mut().unwrap().poll(cx) {
                match r {
                    Ok(r) => *this.slot_b = Some(r),
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
        }
        Poll::Pending
    }
}

pub(crate) async fn copy_with_application_data<'a, const N: usize, R, W>(
    reader: &'a mut R,
    writer: &'a mut W,
    write_prefix: Option<[u8; N]>,
) -> std::io::Result<u64>
where
    R: monoio::io::AsyncReadRent + ?Sized,
    W: monoio::io::AsyncWriteRent + ?Sized,
{
    let mut buf: Vec<u8> = vec![0; COPY_BUF_SIZE];
    buf[0] = APPLICATION_DATA;
    // 0x03, 0x03: tls 1.2
    buf[1] = TLS_MAJOR;
    buf[2] = TLS_MINOR.0;
    // prefix
    let mut buf = if let Some(prefix) = write_prefix {
        assert!(N + TLS_HEADER_SIZE <= COPY_BUF_SIZE);
        unsafe {
            std::ptr::copy_nonoverlapping(prefix.as_ptr(), buf.as_mut_ptr().add(TLS_HEADER_SIZE), N)
        };
        unsafe { buf.set_init(TLS_HEADER_SIZE + N) };
        tracing::debug!("create buf slice with {} bytes prefix", TLS_HEADER_SIZE + N);
        buf.slice_mut(TLS_HEADER_SIZE + N..)
    } else {
        unsafe { buf.set_init(TLS_HEADER_SIZE) };
        tracing::debug!("create buf slice with {} bytes prefix", TLS_HEADER_SIZE);
        buf.slice_mut(TLS_HEADER_SIZE..)
    };

    let mut transfered: u64 = 0;
    loop {
        let (read_res, buf_read) = reader.read(buf).await;
        match read_res {
            Ok(0) => {
                // read closed
                break;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                // retry
                buf = buf_read;
                continue;
            }
            Err(e) => {
                // should return error
                return Err(e);
            }
            Ok(n) => {
                // go write data
                tracing::debug!("copy_with_application_data: read {n} bytes data");
            }
        }
        let mut raw_buf = buf_read.into_inner();
        // convert n to u16 is safe since the buffer will not be resized.
        let n_u16 = (raw_buf.len() - TLS_HEADER_SIZE) as u16;
        // set 3-4 byte of raw_buf as data size
        let size_data = n_u16.to_be_bytes();
        // # Safety
        // We can make sure there are spaces inside the buffer.
        unsafe {
            std::ptr::copy_nonoverlapping(size_data.as_ptr(), raw_buf.as_mut_ptr().add(3), 2);
        }

        tracing::debug!(
            "copy_with_application_data: write {} bytes data",
            raw_buf.len()
        );
        let (write_res, buf_) = writer.write_all(raw_buf).await;
        let n = write_res?;
        transfered += n as u64;
        buf = buf_.slice_mut(TLS_HEADER_SIZE..);
    }
    let _ = writer.shutdown().await;
    Ok(transfered)
}

pub(crate) async fn copy_without_application_data<'a, R, W>(
    reader: &'a mut R,
    writer: &'a mut W,
) -> std::io::Result<u64>
where
    R: monoio::io::AsyncReadRent + ?Sized,
    W: monoio::io::AsyncWriteRent + ?Sized,
{
    let mut buf: Vec<u8> = vec![0; COPY_BUF_SIZE];
    let mut to_copy = 0;
    let mut transfered: u64 = 0;

    unsafe { buf.set_init(0) };
    let mut buf = buf.slice_mut(0..);
    #[allow(unused_labels)]
    'r: loop {
        let (read_res, buf_read) = reader.read(buf).await;
        match read_res {
            Ok(0) => {
                // read closed
                break;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                // retry
                buf = buf_read;
                continue;
            }
            Err(e) => {
                // should return error
                return Err(e);
            }
            Ok(_) => {
                // go write data or read again if data is not enough
            }
        };
        let mut raw_buf = buf_read.into_inner();
        let mut read_index = 0;

        loop {
            // check if we know how much data to copy
            while to_copy == 0 {
                // we should parse header to get its size
                let initialized_length = raw_buf.len();
                if initialized_length < read_index + TLS_HEADER_SIZE {
                    // if the data is not enough for decoding length,
                    // we will move the data left to the front of the buffer.
                    for idx in read_index..initialized_length {
                        raw_buf[idx - read_index] = raw_buf[idx];
                    }
                    // we have to read again because its not enough to parse
                    buf = raw_buf.slice_mut(initialized_length - read_index..);
                    continue 'r;
                }
                // now there is enough data to parse
                if raw_buf[read_index] != APPLICATION_DATA {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unexpected tls content type",
                    ));
                }
                let mut size = [0; 2];
                size[0] = raw_buf[read_index + 3];
                size[1] = raw_buf[read_index + 4];
                to_copy = u16::from_be_bytes(size) as usize;
                // TODO: check how to handle application data with zero size in other libraries?
                // If needed, maybe we should throw an error here.
                read_index += TLS_HEADER_SIZE;
            }

            // now we know how much data to copy
            let initialized = raw_buf.len() - read_index;
            if initialized == 0 {
                // there is no data to copy, we should do read
                buf = raw_buf.slice_mut(0..);
                continue 'r;
            }
            let copy_size = to_copy.min(initialized);
            let write_slice = raw_buf.slice(read_index..read_index + copy_size);

            let (write_res, buf_) = writer.write_all(write_slice).await;
            let n = write_res?;
            read_index += n;
            to_copy -= n;
            transfered += n as u64;
            raw_buf = buf_.into_inner();
        }
    }
    let _ = writer.shutdown().await;
    Ok(transfered)
}
