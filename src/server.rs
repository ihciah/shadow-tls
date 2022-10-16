use std::net::ToSocketAddrs;

use monoio::{
    buf::{IoBuf, IoBufMut, Slice, SliceMut},
    io::{AsyncReadRent, AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt, Splitable},
    net::TcpStream,
};

use crate::{
    stream::{HashedWriteStream, HmacHandler},
    util::{
        copy_until_eof, copy_with_application_data, copy_without_application_data,
        set_tcp_keepalive, ErrGroup, FirstRetGroup, APPLICATION_DATA,
    },
};

/// ShadowTlsServer.
pub struct ShadowTlsServer<RA, RB> {
    handshake_address: RA,
    data_address: RB,
    password: String,
}

impl<HA, DA> ShadowTlsServer<HA, DA> {
    pub fn new(handshake_address: HA, data_address: DA, password: String) -> Self {
        Self {
            handshake_address,
            data_address,
            password,
        }
    }
}

impl<HA, DA> ShadowTlsServer<HA, DA>
where
    HA: ToSocketAddrs,
    DA: ToSocketAddrs,
{
    pub async fn relay(&self, in_stream: TcpStream) -> anyhow::Result<()> {
        let mut out_stream = TcpStream::connect(&self.handshake_address).await?;
        set_tcp_keepalive(&mut out_stream);
        tracing::debug!("handshake server connected");
        let mut in_stream = HashedWriteStream::new(in_stream, self.password.as_bytes())?;
        let hmac = in_stream.hmac_handler();
        let (mut out_r, mut out_w) = out_stream.split();
        let (mut in_r, mut in_w) = in_stream.split();
        let (switch, _) = FirstRetGroup::new(
            copy_until_handshake_finished(&mut in_r, &mut out_w, hmac),
            copy_until_eof(&mut out_r, &mut in_w),
        )
        .await?;
        tracing::debug!("handshake finished, switch: {switch:?}");

        let mut in_stream = in_stream.into_inner();
        let (mut in_r, mut in_w) = in_stream.split();

        match switch {
            SwitchResult::Switch(data_left) => {
                // connect our data server
                let _ = out_stream.shutdown().await;
                drop(out_stream);
                let mut data_stream = TcpStream::connect(&self.data_address).await?;
                set_tcp_keepalive(&mut data_stream);
                tracing::debug!("data server connected, start relay");
                let (mut data_r, mut data_w) = data_stream.split();
                let (result, _) = data_w.write(data_left).await;
                result?;
                ErrGroup::new(
                    copy_with_application_data::<0, _, _>(&mut data_r, &mut in_w, None),
                    copy_without_application_data(&mut in_r, &mut data_w),
                )
                .await?;
            }
            SwitchResult::DirectProxy => {
                ErrGroup::new(copy_until_eof(out_r, in_w), copy_until_eof(in_r, out_w)).await?;
            }
        }
        Ok(())
    }
}

enum SwitchResult {
    Switch(Slice<Vec<u8>>),
    DirectProxy,
}

impl std::fmt::Debug for SwitchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Switch(_) => write!(f, "Switch"),
            Self::DirectProxy => write!(f, "DirectProxy"),
        }
    }
}

async fn copy_until_handshake_finished<R, W>(
    mut read_half: R,
    mut write_half: W,
    hmac: HmacHandler,
) -> std::io::Result<SwitchResult>
where
    R: AsyncReadRent,
    W: AsyncWriteRent,
{
    const HMAC_SIZE: usize = 8;
    const HANDSHAKE: u8 = 0x16;
    const CHANGE_CIPHER_SPEC: u8 = 0x14;
    const HEADER_BUF_SIZE: usize = 5;
    const TLS_MAJOR: u8 = 0x03;
    const TLS_MINOR: (u8, u8) = (0x03, 0x01);
    // We maintain 2 status to make sure current session is in an tls session.
    // This is essential for preventing active detection.
    let mut has_seen_change_cipher_spec = false;
    let mut has_seen_handshake = false;

    // header_buf is used to read handshake frame header, will be a fixed size buffer.
    let mut header_buf = vec![0_u8; HEADER_BUF_SIZE].into_boxed_slice();
    let mut header_read_len = 0;
    let mut header_write_len = 0;
    // data_buf is used to read and write data, and can be expanded.
    let mut data_buf = vec![0_u8; 2048];
    let mut application_data_count: usize = 0;
    loop {
        let header_buf_slice = SliceMut::new(header_buf, header_read_len, HEADER_BUF_SIZE);
        let (res, header_buf_slice_) = read_half.read(header_buf_slice).await;
        header_buf = header_buf_slice_.into_inner();
        let read_len = res?;
        header_read_len += read_len;

        // if EOF, close write half.
        if read_len == 0 {
            let _ = write_half.shutdown().await;
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }

        // We have to relay data now no matter header is enough or not.
        let header_buf_slice_w = Slice::new(header_buf, header_write_len, header_read_len);
        let (res, header_buf_slice_w_) = write_half.write_all(header_buf_slice_w).await;
        header_buf = header_buf_slice_w_.into_inner();
        header_write_len += res?;

        if header_read_len != HEADER_BUF_SIZE {
            // Here we have not got enough data to parse header.
            // continue to read.
            continue;
        }

        // Now header has been read and redirected successfully.
        // We should clear header status.
        header_read_len = 0;
        header_write_len = 0;

        // parse length
        let mut size: [u8; 2] = Default::default();
        size.copy_from_slice(&header_buf[3..5]);
        let data_size = u16::from_be_bytes(size);
        tracing::debug!(
            "read header with type {} and length {}",
            header_buf[0],
            data_size
        );

        // Check data type, if not app data we want, we can forward it directly(in streaming way).
        if header_buf[0] != APPLICATION_DATA || !has_seen_handshake || !has_seen_change_cipher_spec
        {
            // The first packet must be handshake.
            // Also, every packet's version must be valid.
            let valid = (has_seen_handshake || header_buf[0] == HANDSHAKE)
                && header_buf[1] == TLS_MAJOR
                && (header_buf[2] == TLS_MINOR.0 || header_buf[2] == TLS_MINOR.1);
            if header_buf[0] == CHANGE_CIPHER_SPEC {
                has_seen_change_cipher_spec = true;
            }
            if header_buf[0] == HANDSHAKE {
                has_seen_handshake = true;
            }
            // copy data
            let mut to_copy = data_size as usize;
            while to_copy != 0 {
                let max_read = data_buf.capacity().min(to_copy);
                let buf = SliceMut::new(data_buf, 0, max_read);
                let (read_res, buf) = read_half.read(buf).await;

                // if EOF, close write half.
                let read_len = read_res?;
                if read_len == 0 {
                    let _ = write_half.shutdown().await;
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }

                let buf = buf.into_inner().slice(0..read_len);
                let (write_res, buf) = write_half.write_all(buf).await;
                to_copy -= write_res?;
                data_buf = buf.into_inner();
            }
            if !valid {
                return Ok(SwitchResult::DirectProxy);
            }
            continue;
        }

        // Read exact data because we make sure we are in a tls session,
        // and we will behave like a tls server.
        if data_size as usize > data_buf.len() {
            data_buf.reserve(data_size as usize - data_buf.len());
        }
        let slice = data_buf.slice_mut(0..data_size as usize);
        let (data_result, slice_) = read_half.read_exact(slice).await;
        data_result?;
        data_buf = slice_.into_inner();
        tracing::debug!("read data length {}", data_size);

        let mut switch = false;
        application_data_count += 1;
        if data_buf.len() >= HMAC_SIZE {
            let hash = hmac.hash();
            tracing::debug!("hmac calculated: {hash:?}");
            if data_buf[0..HMAC_SIZE] == hash[0..HMAC_SIZE] {
                tracing::debug!("hmac matches");
                switch = true;
            }
        }

        if switch {
            // we will write data to our real server
            let pure_data = data_buf.slice(HMAC_SIZE..);
            return Ok(SwitchResult::Switch(pure_data));
        } else {
            let (write_result, buf) = write_half.write_all(data_buf).await;
            write_result?;
            data_buf = buf;
        }

        if application_data_count > 3 {
            tracing::debug!("hmac not matches after 3 times, fallback to direct");
            return Ok(SwitchResult::DirectProxy);
        }
    }
}
