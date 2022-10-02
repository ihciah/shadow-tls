use std::net::ToSocketAddrs;

use monoio::{
    buf::{IoBuf, IoBufMut, Slice},
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
            monoio::io::copy(&mut out_r, &mut in_w),
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
    // header_buf is used to read handshake frame header, will be a fixed size buffer.
    let mut header_buf = vec![0_u8; 5].into_boxed_slice();
    // data_buf is used to read and write data, and can be expanded.
    let mut data_buf = vec![0_u8; 2048];
    let mut application_data_count: usize = 0;
    loop {
        let (res, header_buf_) = read_half.read_exact(header_buf).await;
        header_buf = header_buf_;
        res?;

        // parse length
        let mut size: [u8; 2] = Default::default();
        size.copy_from_slice(&header_buf[3..5]);
        let data_size = u16::from_be_bytes(size);
        tracing::debug!(
            "read header with type {} and length {}",
            header_buf[0],
            data_size
        );

        // read data
        if data_size as usize > data_buf.len() {
            data_buf.reserve(data_size as usize - data_buf.len());
        }
        let slice = data_buf.slice_mut(0..data_size as usize);
        let (data_result, slice_) = read_half.read_exact(slice).await;
        data_result?;
        data_buf = slice_.into_inner();
        tracing::debug!("read data length {}", data_size);

        let mut switch = false;
        if header_buf[0] == APPLICATION_DATA {
            application_data_count += 1;
            if data_buf.len() >= HMAC_SIZE {
                let hash = hmac.hash();
                tracing::debug!("hmac calculated: {hash:?}");
                if data_buf[0..HMAC_SIZE] == hash[0..HMAC_SIZE] {
                    tracing::debug!("hmac matches");
                    switch = true;
                }
            }
        }

        if switch {
            // we will write data to our real server
            let pure_data = data_buf.slice(HMAC_SIZE..);
            return Ok(SwitchResult::Switch(pure_data));
        }

        // copy header and data
        let (write_result, buf) = write_half.write_all(header_buf).await;
        write_result?;
        header_buf = buf;
        let (write_result, buf) = write_half.write_all(data_buf).await;
        write_result?;
        data_buf = buf;

        if application_data_count > 3 {
            tracing::debug!("hmac not matches after 3 times, fallback to direct");
            return Ok(SwitchResult::DirectProxy);
        }
    }
}
