use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::Result;
use monoio::{
    buf::IoBufMut,
    io::{AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt},
    net::{
        tcp::{TcpReadHalf, TcpWriteHalf},
        TcpStream,
    },
};
use monoio_rustls::TlsConnector;
use rustls::{version::TLS12, OwnedTrustAnchor, RootCertStore, ServerName};
use tracing::{debug, info};

pub struct ShadowTlsClient<A> {
    tls_connector: TlsConnector,
    server_name: ServerName,
    address: A,
}

impl<A> ShadowTlsClient<A> {
    pub fn new(server_name: &str, address: A) -> Result<Self> {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let tls_config = rustls::ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&TLS12])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let tls_connector = TlsConnector::from(tls_config);
        let server_name = ServerName::try_from(server_name)?;
        Ok(Self {
            tls_connector,
            server_name,
            address,
        })
    }

    pub async fn process(&self, mut in_stream: TcpStream, addr: SocketAddr) -> Result<()>
    where
        A: std::net::ToSocketAddrs,
    {
        let mut out_stream = self.connect().await?;
        let (out_r, out_w) = out_stream.split();
        let (in_r, in_w) = in_stream.split();
        let (a, b) = monoio::join!(copy_until_eof(out_r, in_w), copy_until_eof(in_r, out_w),);
        let (_, _) = (a?, b?);
        info!("Relay for {addr} finished");
        Ok(())
    }

    async fn connect(&self) -> Result<TcpStream>
    where
        A: std::net::ToSocketAddrs,
    {
        let stream = TcpStream::connect(&self.address).await?;
        let _ = stream.set_tcp_keepalive(
            Some(Duration::from_secs(90)),
            Some(Duration::from_secs(90)),
            Some(2),
        );
        debug!("tcp connected, start handshaking");
        let tls_stream = self
            .tls_connector
            .connect(self.server_name.clone(), stream)
            .await?;
        debug!("tls handshake finished");
        let (io, _) = tls_stream.into_parts();
        Ok(io)
    }
}

pub struct ShadowTlsServer<RA, RB> {
    tls_remote: RA,
    real_remote: RB,
}

impl<RA, RB> ShadowTlsServer<RA, RB> {
    pub fn new(tls_remote: RA, real_remote: RB) -> Self {
        Self {
            tls_remote,
            real_remote,
        }
    }

    pub async fn process(&self, mut in_stream: TcpStream, addr: SocketAddr) -> Result<()>
    where
        RA: std::net::ToSocketAddrs,
        RB: std::net::ToSocketAddrs,
    {
        Self::relay(&mut in_stream, &self.tls_remote, true).await?;
        info!("Handshake for {addr} finished");
        Self::relay(&mut in_stream, &self.real_remote, false).await?;
        info!("Relay for {addr} finished");
        Ok(())
    }

    async fn relay<A: std::net::ToSocketAddrs>(
        in_stream: &mut TcpStream,
        address: A,
        handshake: bool,
    ) -> Result<()> {
        let mut out_stream = TcpStream::connect(address).await?;
        let (out_r, out_w) = out_stream.split();
        let (in_r, in_w) = in_stream.split();
        match handshake {
            true => {
                TaskPair::new(
                    copy_until_handshake_finished(out_r, in_w),
                    copy_until_handshake_finished(in_r, out_w),
                )
                .await?;
            }

            false => {
                TaskPair::new(copy_until_eof(out_r, in_w), copy_until_eof(in_r, out_w)).await?;
            }
        };
        Ok(())
    }
}

async fn copy_until_handshake_finished<'a>(
    mut read_half: TcpReadHalf<'a>,
    mut write_half: TcpWriteHalf<'a>,
) -> Result<()> {
    const HANDSHAKE: u8 = 0x16;
    const CHANGE_CIPHER_SPEC: u8 = 0x14;
    // header_buf is used to read handshake frame header, will be a fixed size buffer.
    let mut header_buf = Some(vec![0_u8; 5]);
    // data_buf is used to read and write data, and can be expanded.
    let mut data_buf = Some(vec![0_u8; 2048]);
    let mut has_seen_change_cipher_spec = false;

    loop {
        // read exact 5 bytes
        let hb = header_buf.take().unwrap();
        let (res, hb) = read_half.read_exact(hb).await;
        res?;

        // parse length
        let mut size: [u8; 2] = Default::default();
        size.copy_from_slice(&hb[3..5]);
        let data_size = u16::from_be_bytes(size);

        // copy header and that much data
        let (res, hb) = write_half.write_all(hb).await;
        res?;
        let mut db = data_buf.take().unwrap();
        if data_size as usize > db.len() {
            db.reserve(data_size as usize - db.len());
        }
        let slice = db.slice_mut(0..data_size as usize);
        let (res, slice) = read_half.read_exact(slice).await;
        let db = slice.into_inner();
        res?;
        let (res, db) = write_half.write_all(db).await;
        res?;
        data_buf = Some(db);

        // check header type
        let header_ref = header_buf.insert(hb);
        if header_ref[0] != HANDSHAKE {
            if header_ref[0] != CHANGE_CIPHER_SPEC {
                return Err(anyhow::anyhow!("unexpected tls frame type"));
            }
            if !has_seen_change_cipher_spec {
                has_seen_change_cipher_spec = true;
                continue;
            }
        }
        if has_seen_change_cipher_spec {
            break;
        }
    }
    Ok(())
}

async fn copy_until_eof<'a>(
    mut read_half: TcpReadHalf<'a>,
    mut write_half: TcpWriteHalf<'a>,
) -> Result<()> {
    let copy_result = monoio::io::copy(&mut read_half, &mut write_half).await;
    write_half.shutdown().await?;
    copy_result?;
    Ok(())
}

pin_project_lite::pin_project! {
    struct TaskPair<FA, FB, A, B> {
        #[pin]
        future_a: FA,
        #[pin]
        future_b: FB,
        slot_a: Option<A>,
        slot_b: Option<B>
    }
}

impl<FA, FB, A, B> TaskPair<FA, FB, A, B>
where
    FA: Future<Output = Result<A>>,
    FB: Future<Output = Result<B>>,
{
    fn new(future_a: FA, future_b: FB) -> Self {
        Self {
            future_a,
            future_b,
            slot_a: None,
            slot_b: None,
        }
    }
}

impl<FA, FB, A, B> Future for TaskPair<FA, FB, A, B>
where
    FA: Future<Output = Result<A>>,
    FB: Future<Output = Result<B>>,
{
    type Output = Result<(A, B)>;

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
