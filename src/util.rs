use std::{ptr::copy_nonoverlapping, time::Duration};

use byteorder::{BigEndian, WriteBytesExt};
use local_sync::oneshot::{Receiver, Sender};
use monoio::{
    buf::IoBufMut,
    io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt, Splitable},
    net::TcpStream,
};

use hmac::Mac;
use rand::Rng;
use sha2::{Digest, Sha256};

use prelude::*;

pub mod prelude {
    pub const TLS_MAJOR: u8 = 0x03;
    pub const TLS_MINOR: (u8, u8) = (0x03, 0x01);
    pub const SNI_EXT_TYPE: u16 = 0;
    pub const TLS_RANDOM_SIZE: usize = 32;
    pub const TLS_HEADER_SIZE: usize = 5;
    pub const TLS_SESSION_ID_SIZE: usize = 32;

    pub const CLIENT_HELLO: u8 = 0x01;
    pub const SERVER_HELLO: u8 = 0x02;
    pub const ALERT: u8 = 0x15;
    pub const HANDSHAKE: u8 = 0x16;
    pub const APPLICATION_DATA: u8 = 0x17;
    pub const CHANGE_CIPHER_SPEC: u8 = 0x14;

    pub const SERVER_RANDOM_IDX: usize = TLS_HEADER_SIZE + 1 + 3 + 2;
    pub const SESSION_ID_LEN_IDX: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;
    pub const TLS_HMAC_HEADER_SIZE: usize = TLS_HEADER_SIZE + HMAC_SIZE;

    pub const COPY_BUF_SIZE: usize = 4096;
    pub const HMAC_SIZE: usize = 4;
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

pub async fn copy_bidirectional(l: &mut TcpStream, r: &mut TcpStream) {
    let (lr, lw) = l.split();
    let (rr, rw) = r.split();
    let _ = monoio::join!(copy_until_eof(lr, rw), copy_until_eof(rr, lw));
}

pub fn mod_tcp_conn(conn: &mut TcpStream, keepalive: bool, nodelay: bool) {
    if keepalive {
        let _ = conn.set_tcp_keepalive(
            Some(Duration::from_secs(90)),
            Some(Duration::from_secs(90)),
            Some(2),
        );
    }
    let _ = conn.set_nodelay(nodelay);
}

pub struct Hmac(hmac::Hmac<sha1::Sha1>);

impl Hmac {
    #[inline]
    pub fn new(password: &str, init_data: (&[u8], &[u8])) -> Self {
        // Note: infact new_from_slice never returns Err.
        let mut hmac: hmac::Hmac<sha1::Sha1> =
            hmac::Hmac::new_from_slice(password.as_bytes()).expect("unable to build hmac instance");
        hmac.update(init_data.0);
        hmac.update(init_data.1);
        Self(hmac)
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    #[inline]
    pub fn finalize(&self) -> [u8; HMAC_SIZE] {
        let hmac = self.0.clone();
        let hash = hmac.finalize().into_bytes();
        let mut res = [0; HMAC_SIZE];
        unsafe { copy_nonoverlapping(hash.as_slice().as_ptr(), res.as_mut_ptr(), HMAC_SIZE) };
        res
    }

    #[inline]
    pub fn to_owned(&self) -> Self {
        Self(self.0.clone())
    }
}

#[inline]
pub fn xor_slice(data: &mut [u8], key: &[u8]) {
    data.iter_mut()
        .zip(key.iter().cycle())
        .for_each(|(d, k)| *d ^= k);
}

#[inline]
pub fn kdf(password: &str, server_random: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(server_random);
    let hash = hasher.finalize();
    hash.to_vec()
}

pub async fn verified_relay(
    mut raw: TcpStream,
    mut tls: TcpStream,
    mut hmac_add: Hmac,
    mut hmac_verify: Hmac,
) {
    tracing::debug!("verified relay started");
    let (mut tls_read, mut tls_write) = tls.split();
    let (mut raw_read, mut raw_write) = raw.split();
    let (mut notfied, mut notifier) = local_sync::oneshot::channel::<()>();
    let _ = monoio::join!(
        async {
            copy_remove_appdata_and_verify(
                &mut tls_read,
                &mut raw_write,
                &mut hmac_verify,
                &mut notifier,
            )
            .await;
            let _ = raw_write.shutdown().await;
        },
        async {
            copy_add_appdata(&mut raw_read, &mut tls_write, &mut hmac_add, &mut notfied).await;
            let _ = tls_write.shutdown().await;
        }
    );
}

/// Remove application data header, verify hmac, remove the
/// hmac header and copy.
async fn copy_remove_appdata_and_verify(
    read: impl AsyncReadRent,
    mut write: impl AsyncWriteRent,
    hmac: &mut Hmac,
    alert_notifier: &mut Receiver<()>,
) {
    const INIT_BUFFER_SIZE: usize = 2048;

    let mut decoder = BufferFrameDecoder::new(read, INIT_BUFFER_SIZE);
    loop {
        let maybe_frame = match decoder.next().await {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("io error {e}");
                alert_notifier.close();
                return;
            }
        };
        let frame = match maybe_frame {
            Some(frame) => frame,
            None => {
                // EOF
                return;
            }
        };
        // validate frame
        match frame[0] {
            ALERT => {
                return;
            }
            APPLICATION_DATA => {
                if verify_appdata(frame, hmac) {
                    let (res, _) = write
                        .write_all(unsafe {
                            monoio::buf::RawBuf::new(
                                frame.as_ptr().add(TLS_HMAC_HEADER_SIZE),
                                frame.len() - TLS_HMAC_HEADER_SIZE,
                            )
                        })
                        .await;
                    if let Err(e) = res {
                        tracing::error!("write data server failed: {e}");
                        alert_notifier.close();
                        return;
                    }
                } else {
                    alert_notifier.close();
                    return;
                }
            }
            _ => {
                alert_notifier.close();
                return;
            }
        }
    }
}

async fn copy_add_appdata(
    mut read: impl AsyncReadRent,
    mut write: impl AsyncWriteRent,
    hmac: &mut Hmac,
    alert_notified: &mut Sender<()>,
) {
    const DEFAULT_DATA: [u8; TLS_HMAC_HEADER_SIZE] =
        [APPLICATION_DATA, TLS_MAJOR, TLS_MINOR.0, 0, 0, 0, 0, 0, 0];

    let mut buffer = Vec::with_capacity(COPY_BUF_SIZE);
    buffer.extend_from_slice(&DEFAULT_DATA);

    let alert_notified = alert_notified.closed();
    monoio::pin!(alert_notified);

    loop {
        monoio::select! {
            _ = &mut alert_notified => {
                send_alert(&mut write).await;
                return;
            },
            (res, buf) = read.read(buffer.slice_mut(TLS_HMAC_HEADER_SIZE..)) => {
                if matches!(res, Ok(0) | Err(_)) {
                    send_alert(&mut write).await;
                    return;
                }
                buffer = buf.into_inner();
                let frame_len = buffer.len() - TLS_HEADER_SIZE;
                (&mut buffer[3..5])
                    .write_u16::<BigEndian>(frame_len as u16)
                    .unwrap();

                hmac.update(&buffer[TLS_HMAC_HEADER_SIZE..]);
                let hmac_val = hmac.finalize();
                hmac.update(&hmac_val);
                unsafe { copy_nonoverlapping(hmac_val.as_ptr(), buffer.as_mut_ptr().add(TLS_HEADER_SIZE), HMAC_SIZE) };

                let (res, buf) = write.write_all(buffer).await;
                buffer = buf;

                if res.is_err() {
                    return;
                }
            }
        }
    }
}

fn verify_appdata(frame: &[u8], hmac: &mut Hmac) -> bool {
    if frame[1] != TLS_MAJOR || frame[2] != TLS_MINOR.0 || frame.len() < TLS_HMAC_HEADER_SIZE {
        return false;
    }
    hmac.update(&frame[TLS_HMAC_HEADER_SIZE..]);
    let mut hmac_val = [0; HMAC_SIZE];
    unsafe {
        copy_nonoverlapping(
            frame.as_ptr().add(TLS_HEADER_SIZE),
            hmac_val.as_mut_ptr(),
            HMAC_SIZE,
        )
    }
    let hmac_real = hmac.finalize();
    hmac.update(&hmac_real);
    hmac_val == hmac_real
}

async fn send_alert(mut w: impl AsyncWriteRent) {
    const FULL_SIZE: u8 = 31;
    const HEADER: [u8; TLS_HEADER_SIZE] = [
        ALERT,
        TLS_MAJOR,
        TLS_MINOR.0,
        0x00,
        FULL_SIZE - TLS_HEADER_SIZE as u8,
    ];

    let mut buf = vec![0; FULL_SIZE as usize];
    unsafe { copy_nonoverlapping(HEADER.as_ptr(), buf.as_mut_ptr(), HEADER.len()) };
    rand::thread_rng().fill(&mut buf[HEADER.len()..]);

    let _ = w.write_all(buf).await;
}

trait ReadExt {
    fn unexpected_eof(self) -> Self;
}

impl ReadExt for std::io::Result<usize> {
    #[inline]
    fn unexpected_eof(self) -> Self {
        self.and_then(|n| match n {
            0 => Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            )),
            _ => Ok(n),
        })
    }
}

struct BufferFrameDecoder<T> {
    reader: T,
    buffer: Option<Vec<u8>>,
    read_pos: usize,
}

impl<T: AsyncReadRent> BufferFrameDecoder<T> {
    #[inline]
    fn new(reader: T, capacity: usize) -> Self {
        Self {
            reader,
            buffer: Some(Vec::with_capacity(capacity)),
            read_pos: 0,
        }
    }

    // note: uncancelable
    async fn next(&mut self) -> std::io::Result<Option<&[u8]>> {
        loop {
            let l = self.get_buffer().len();
            match l {
                0 => {
                    // empty buffer
                    if self.feed_data().await? == 0 {
                        // eof
                        return Ok(None);
                    }
                    continue;
                }
                1..=4 => {
                    // has header but not enough to parse length
                    self.feed_data().await.unexpected_eof()?;
                    continue;
                }
                _ => {
                    // buffer is enough to parse length
                    let buffer = self.get_buffer();
                    let mut size: [u8; 2] = Default::default();
                    size.copy_from_slice(&buffer[3..5]);
                    let data_size = u16::from_be_bytes(size) as usize;
                    if buffer.len() < TLS_HEADER_SIZE + data_size {
                        // we will do compact and read more data
                        self.reserve(TLS_HEADER_SIZE + data_size);
                        self.feed_data().await.unexpected_eof()?;
                        continue;
                    }
                    // buffer is enough to parse data
                    let slice = &self.buffer.as_ref().unwrap()
                        [self.read_pos..self.read_pos + TLS_HEADER_SIZE + data_size];
                    self.read_pos += TLS_HEADER_SIZE + data_size;
                    return Ok(Some(slice));
                }
            }
        }
    }

    // note: uncancelable
    async fn feed_data(&mut self) -> std::io::Result<usize> {
        self.compact();
        let buffer = self.buffer.take().unwrap();
        let idx = buffer.len();
        let read_buffer = buffer.slice_mut(idx..);
        let (res, read_buffer) = self.reader.read(read_buffer).await;
        self.buffer = Some(read_buffer.into_inner());
        res
    }

    #[inline]
    fn get_buffer(&self) -> &[u8] {
        &self.buffer.as_ref().unwrap()[self.read_pos..]
    }

    /// Make sure the Vec has at least that capacity.
    #[inline]
    fn reserve(&mut self, n: usize) {
        let buf = self.buffer.as_mut().unwrap();
        if n > buf.len() {
            buf.reserve(n - buf.len());
        }
    }

    #[inline]
    fn compact(&mut self) {
        if self.read_pos == 0 {
            return;
        }
        let buffer = self.buffer.as_mut().unwrap();
        let ptr = buffer.as_mut_ptr();
        let readable_len = buffer.len() - self.read_pos;
        unsafe {
            std::ptr::copy(ptr.add(self.read_pos), ptr, readable_len);
            buffer.set_init(readable_len);
        }
        self.read_pos = 0;
    }
}
