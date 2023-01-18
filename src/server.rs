use std::net::ToSocketAddrs;

use monoio::{
    buf::{IoBuf, Slice, SliceMut},
    io::{AsyncReadRent, AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt, Splitable},
    net::TcpStream,
};

use crate::{
    stream::{HashedWriteStream, HmacHandler},
    util::{
        copy_until_eof, copy_with_application_data, copy_without_application_data, mod_tcp_conn,
        ErrGroup, FirstRetGroup, APPLICATION_DATA,
    },
    Opts,
};

/// ShadowTlsServer.
pub struct ShadowTlsServer<RA, RB> {
    handshake_address: RA,
    data_address: RB,
    password: String,
    opts: Opts,
}

impl<HA, DA> ShadowTlsServer<HA, DA> {
    pub fn new(handshake_address: HA, data_address: DA, password: String, opts: Opts) -> Self {
        Self {
            handshake_address,
            data_address,
            password,
            opts,
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
        mod_tcp_conn(&mut out_stream, true, !self.opts.disable_nodelay);
        tracing::debug!("handshake server connected");
        let mut in_stream = HashedWriteStream::new(in_stream, self.password.as_bytes())?;
        let mut hmac = in_stream.hmac_handler();
        let (mut out_r, mut out_w) = out_stream.split();
        let (mut in_r, mut in_w) = in_stream.split();
        let (switch, cp) = FirstRetGroup::new(
            copy_until_handshake_finished(&mut in_r, &mut out_w, &hmac),
            Box::pin(copy_until_eof(&mut out_r, &mut in_w)),
        )
        .await?;
        hmac.disable();
        tracing::debug!("handshake finished, switch: {switch:?}");

        match switch {
            SwitchResult::Switch(data_left) => {
                drop(cp);
                let mut in_stream = in_stream.into_inner();
                let (mut in_r, mut in_w) = in_stream.split();

                // connect our data server
                let _ = out_stream.shutdown().await;
                drop(out_stream);
                let mut data_stream = TcpStream::connect(&self.data_address).await?;
                mod_tcp_conn(&mut data_stream, true, !self.opts.disable_nodelay);
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
            SwitchResult::DirectProxy => match cp {
                crate::util::FutureOrOutput::Future(cp) => {
                    ErrGroup::new(cp, copy_until_eof(in_r, out_w)).await?;
                }
                crate::util::FutureOrOutput::Output(_) => {
                    copy_until_eof(in_r, out_w).await?;
                }
            },
        }
        Ok(())
    }
}

enum SwitchResult {
    Switch(Vec<u8>),
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
    hmac: &HmacHandler,
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
    let mut data_hmac_buf = vec![0_u8; HMAC_SIZE].into_boxed_slice();
    let mut data_buf = vec![0_u8; 2048];
    let mut application_data_count: usize = 0;
    loop {
        let header_buf_slice = SliceMut::new(header_buf, header_read_len, HEADER_BUF_SIZE);
        let (res, header_buf_slice_) = read_half.read(header_buf_slice).await;
        header_buf = header_buf_slice_.into_inner();
        let read_len = res?;
        header_read_len += read_len;

        // If EOF, close write half.
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

        // Parse length.
        let mut size: [u8; 2] = Default::default();
        size.copy_from_slice(&header_buf[3..5]);
        let data_size = u16::from_be_bytes(size) as usize;
        tracing::debug!(
            "read header with type {} and length {}",
            header_buf[0],
            data_size
        );

        // Check data type, if not app data we want, we can forward it directly(in streaming way).
        if header_buf[0] != APPLICATION_DATA
            || !has_seen_handshake
            || !has_seen_change_cipher_spec
            || data_size < HMAC_SIZE
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
            // Copy data.
            let mut to_copy = data_size;
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
            tracing::debug!("copied data with length {:?}", data_size);
            if !valid {
                tracing::debug!("early invalid tls: header {:?}", &header_buf[..3]);
                return Ok(SwitchResult::DirectProxy);
            }
            continue;
        }

        // Here we need to check hmac.
        // We have to read and copy the maybe_hmac.
        // Note: Send this 8 byte to remote does not matters:
        // If the data is sent by our authorized client, the handshake server must within
        // a tls session. So it must read exact that length data and then process it.
        // For this reason, sending 8 byte hmac will not cause the handshake server
        // shuting down the connection.
        // If the data in sent by an attacker, we must behaves like a tcp proxy so it seems
        // we are the handshake server.
        let mut hmac_read_len = 0;
        while hmac_read_len < HMAC_SIZE {
            let buf = SliceMut::new(data_hmac_buf, hmac_read_len, HMAC_SIZE);
            let (res, buf_) = read_half.read(buf).await;
            // if EOF, close write half.
            let read_len = res?;
            if read_len == 0 {
                let _ = write_half.shutdown().await;
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }

            let buf = Slice::new(buf_.into_inner(), hmac_read_len, hmac_read_len + read_len);
            let (write_res, buf_) = write_half.write_all(buf).await;
            write_res?;
            hmac_read_len += read_len;
            data_hmac_buf = buf_.into_inner();
        }

        // Now hmac has been read and copied.
        // If hmac matches, we need to read current data and return.
        let hash = hmac.hash();
        tracing::debug!("hmac calculated: {hash:?}");
        if data_hmac_buf[0..HMAC_SIZE] == hash[0..HMAC_SIZE] {
            tracing::debug!("hmac matches");
            let pure_data = vec![0; data_size - HMAC_SIZE];
            let (read_res, pure_data) = read_half.read_exact(pure_data).await;
            read_res?;
            return Ok(SwitchResult::Switch(pure_data));
        }

        // Now hmac does not match. We have to acc the counter and do copy.
        application_data_count += 1;
        let mut to_copy = data_size - HMAC_SIZE;
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

        if application_data_count > 3 {
            tracing::debug!("hmac not matches after 3 times, fallback to direct");
            return Ok(SwitchResult::DirectProxy);
        }
    }
}
