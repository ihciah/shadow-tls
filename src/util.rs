use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use monoio::{
    buf::{IoBuf, IoBufMut},
    io::AsyncWriteRentExt,
    net::TcpStream,
};

pin_project_lite::pin_project! {
    /// ErrGroup works like ErrGroup in golang.
    /// If the two futures all finished with Ok, self is finished with Ok.
    /// If any one of them finished with Err, self is finished with Err.
    pub struct ErrGroup<FA, FB, A, B, E> {
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
    pub fn new(future_a: FA, future_b: FB) -> Self {
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
    pub struct FirstRetGroup<FA, FB, B, E> {
        #[pin]
        future_a: FA,
        #[pin]
        future_b: Option<FB>,
        slot_b: Option<B>,
        marker: PhantomData<E>,
    }
}

pub enum FutureOrOutput<F, R, E>
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
    pub fn new(future_a: FA, future_b: FB) -> Self {
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

pub async fn copy_until_eof<R, W>(mut read_half: R, mut write_half: W) -> std::io::Result<()>
where
    R: monoio::io::AsyncReadRent,
    W: monoio::io::AsyncWriteRent,
{
    let copy_result = monoio::io::copy(&mut read_half, &mut write_half).await;
    let _ = write_half.shutdown().await;
    copy_result?;
    Ok(())
}

// BUF_SIZE < u16::MAX, BUF_SIZE > HEADER_SIZE + copy_with_application_data::N
// 4K or 8K is enough.
const BUF_SIZE: usize = 4096;
// HEADER_SIZE: 0 is application data, 1-2 is tls1.2, 3-4 is payload length.
const HEADER_SIZE: usize = 5;
pub const APPLICATION_DATA: u8 = 0x17;

pub async fn copy_with_application_data<'a, const N: usize, R, W>(
    reader: &'a mut R,
    writer: &'a mut W,
    write_prefix: Option<[u8; N]>,
) -> std::io::Result<u64>
where
    R: monoio::io::AsyncReadRent + ?Sized,
    W: monoio::io::AsyncWriteRent + ?Sized,
{
    let mut buf: Vec<u8> = vec![0; BUF_SIZE];
    buf[0] = APPLICATION_DATA;
    // 0x03, 0x03: tls 1.2
    buf[1] = 0x03;
    buf[2] = 0x03;
    // prefix
    let mut buf = if let Some(prefix) = write_prefix {
        unsafe {
            std::ptr::copy_nonoverlapping(prefix.as_ptr(), buf.as_mut_ptr().add(HEADER_SIZE), N)
        };
        unsafe { buf.set_init(HEADER_SIZE + N) };
        tracing::debug!("create buf slice with {} bytes prefix", HEADER_SIZE + N);
        buf.slice_mut(HEADER_SIZE + N..)
    } else {
        unsafe { buf.set_init(HEADER_SIZE) };
        tracing::debug!("create buf slice with {} bytes prefix", HEADER_SIZE);
        buf.slice_mut(HEADER_SIZE..)
    };

    let mut transfered: u64 = 0;
    loop {
        let (read_res, buf_read) = reader.read(buf).await;
        match read_res {
            Ok(n) if n == 0 => {
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
        let n_u16 = (raw_buf.len() - HEADER_SIZE) as u16;
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
        tracing::debug!("reset buf slice with {} bytes prefix", HEADER_SIZE);
        buf = buf_.slice_mut(HEADER_SIZE..);
    }
    let _ = writer.shutdown().await;
    Ok(transfered)
}

pub async fn copy_without_application_data<'a, R, W>(
    reader: &'a mut R,
    writer: &'a mut W,
) -> std::io::Result<u64>
where
    R: monoio::io::AsyncReadRent + ?Sized,
    W: monoio::io::AsyncWriteRent + ?Sized,
{
    let mut buf: Vec<u8> = vec![0; BUF_SIZE];
    let mut to_copy = 0;
    let mut transfered: u64 = 0;

    unsafe { buf.set_init(0) };
    let mut buf = buf.slice_mut(0..);
    #[allow(unused_labels)]
    'r: loop {
        let (read_res, buf_read) = reader.read(buf).await;
        match read_res {
            Ok(n) if n == 0 => {
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
                if initialized_length < read_index + HEADER_SIZE {
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
                read_index += HEADER_SIZE;
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

pub fn set_tcp_keepalive(conn: &mut TcpStream) {
    let _ = conn.set_tcp_keepalive(
        Some(Duration::from_secs(90)),
        Some(Duration::from_secs(90)),
        Some(2),
    );
}
