use std::{
    ptr::{copy, copy_nonoverlapping},
    rc::Rc,
    sync::Arc,
};

use anyhow::bail;
use byteorder::{BigEndian, WriteBytesExt};
use monoio::{
    buf::IoBufMut,
    io::{AsyncReadRent, AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt, Splitable},
    net::TcpStream,
};
use monoio_rustls_fork_shadow_tls::TlsConnector;
use rand::{prelude::Distribution, seq::SliceRandom, Rng};
use rustls_fork_shadow_tls::{OwnedTrustAnchor, RootCertStore, ServerName};

use crate::{
    helper_v2::{copy_with_application_data, copy_without_application_data, HashedReadStream},
    util::{
        bind_with_pretty_error, kdf, mod_tcp_conn, prelude::*, verified_relay, xor_slice, Hmac,
        V3Mode,
    },
};

const FAKE_REQUEST_LENGTH_RANGE: (usize, usize) = (16, 64);

/// ShadowTlsClient.
#[derive(Clone)]
pub struct ShadowTlsClient<LA, TA> {
    listen_addr: Arc<LA>,
    target_addr: Arc<TA>,
    tls_connector: TlsConnector,
    tls_names: Arc<TlsNames>,
    password: Arc<String>,
    nodelay: bool,
    v3: V3Mode,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TlsNames(Vec<ServerName>);

impl TlsNames {
    pub fn random_choose(&self) -> &ServerName {
        self.0.choose(&mut rand::thread_rng()).unwrap()
    }
}

impl TryFrom<&str> for TlsNames {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let v: Result<Vec<_>, _> = value.trim().split(';').map(ServerName::try_from).collect();
        let v = v.map_err(Into::into).and_then(|v| {
            if v.is_empty() {
                Err(anyhow::anyhow!("empty tls names"))
            } else {
                Ok(v)
            }
        })?;
        Ok(Self(v))
    }
}

impl std::fmt::Display for TlsNames {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

pub fn parse_client_names(addrs: &str) -> anyhow::Result<TlsNames> {
    TlsNames::try_from(addrs)
}

#[derive(Default, Debug)]
pub struct TlsExtConfig {
    alpn: Option<Vec<Vec<u8>>>,
}

impl TlsExtConfig {
    #[allow(unused)]
    pub fn new(alpn: Option<Vec<Vec<u8>>>) -> TlsExtConfig {
        TlsExtConfig { alpn }
    }
}

impl From<Option<Vec<String>>> for TlsExtConfig {
    fn from(maybe_alpns: Option<Vec<String>>) -> Self {
        Self {
            alpn: maybe_alpns.map(|alpns| alpns.into_iter().map(Into::into).collect()),
        }
    }
}

impl std::fmt::Display for TlsExtConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.alpn.as_ref() {
            Some(alpns) => {
                write!(f, "ALPN(Some(")?;
                for alpn in alpns.iter() {
                    write!(f, "{},", String::from_utf8_lossy(alpn))?;
                }
                write!(f, "))")?;
            }
            None => {
                write!(f, "ALPN(None)")?;
            }
        }
        Ok(())
    }
}

impl<LA, TA> ShadowTlsClient<LA, TA> {
    /// Create new ShadowTlsClient.
    pub fn new(
        listen_addr: LA,
        target_addr: TA,
        tls_names: TlsNames,
        tls_ext_config: TlsExtConfig,
        password: String,
        nodelay: bool,
        v3: V3Mode,
    ) -> anyhow::Result<Self> {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        // TLS 1.2 and TLS 1.3 is enabled.
        let mut tls_config = rustls_fork_shadow_tls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Set tls config
        if let Some(alpn) = tls_ext_config.alpn {
            tls_config.alpn_protocols = alpn;
        }

        let tls_connector = TlsConnector::from(tls_config);

        Ok(Self {
            listen_addr: Arc::new(listen_addr),
            target_addr: Arc::new(target_addr),
            tls_connector,
            tls_names: Arc::new(tls_names),
            password: Arc::new(password),
            nodelay,
            v3,
        })
    }

    /// Serve a raw connection.
    pub async fn serve(self) -> anyhow::Result<()>
    where
        LA: std::net::ToSocketAddrs + 'static,
        TA: std::net::ToSocketAddrs + 'static,
    {
        let listener = bind_with_pretty_error(self.listen_addr.as_ref())?;
        let shared = Rc::new(self);
        loop {
            match listener.accept().await {
                Ok((mut conn, addr)) => {
                    tracing::info!("Accepted a connection from {addr}");
                    let client = shared.clone();
                    mod_tcp_conn(&mut conn, true, shared.nodelay);
                    monoio::spawn(async move {
                        let _ = match client.v3.enabled() {
                            false => client.relay_v2(conn).await,
                            true => client.relay_v3(conn).await,
                        };
                        tracing::info!("Relay for {addr} finished");
                    });
                }
                Err(e) => {
                    tracing::error!("Accept failed: {e}");
                }
            }
        }
    }

    /// Main relay for V2 protocol.
    async fn relay_v2(&self, mut in_stream: TcpStream) -> anyhow::Result<()>
    where
        TA: std::net::ToSocketAddrs,
    {
        let (mut out_stream, hash, session) = self.connect_v2().await?;
        let mut hash_8b = [0; 8];
        unsafe { std::ptr::copy_nonoverlapping(hash.as_ptr(), hash_8b.as_mut_ptr(), 8) };
        let (out_r, mut out_w) = out_stream.split();
        let (mut in_r, mut in_w) = in_stream.split();
        let mut session_filtered_out_r = crate::helper_v2::SessionFilterStream::new(session, out_r);
        let (a, b) = monoio::join!(
            copy_without_application_data(&mut session_filtered_out_r, &mut in_w),
            copy_with_application_data(&mut in_r, &mut out_w, Some(hash_8b))
        );
        let (_, _) = (a?, b?);
        Ok(())
    }

    /// Main relay for V3 protocol.
    async fn relay_v3(&self, in_stream: TcpStream) -> anyhow::Result<()>
    where
        TA: std::net::ToSocketAddrs,
    {
        let mut stream = TcpStream::connect(self.target_addr.as_ref()).await?;
        mod_tcp_conn(&mut stream, true, self.nodelay);
        tracing::debug!("tcp connected, start handshaking");

        // stage1: handshake with wrapper
        let hamc_sr = Hmac::new(&self.password, (&[], &[]));
        let stream = StreamWrapper::new(stream, &self.password);
        let sni = self.tls_names.random_choose().clone();
        let tls_stream = self
            .tls_connector
            .connect_with_session_id_generator(sni, stream, move |data| {
                generate_session_id(&hamc_sr, data)
            })
            .await?;
        tracing::debug!("handshake success");
        let (stream, session) = tls_stream.into_parts();
        let authorized = stream.authorized();
        let maybe_srh = stream
            .state()
            .as_ref()
            .map(|s| (s.server_random, s.hmac.to_owned()));
        let stream = stream.into_inner();

        // stage2:
        if maybe_srh.is_none() || !authorized && self.v3.strict() {
            tracing::warn!("V3 strict enabled: traffic hijacked or TLS1.3 is not supported");
            let tls_stream = monoio_rustls_fork_shadow_tls::ClientTlsStream::new(stream, session);
            if let Err(e) = fake_request(tls_stream).await {
                bail!("traffic hijacked or TLS1.3 is not supported, fake request fail: {e}");
            }
            bail!("traffic hijacked or TLS1.3 is not supported, but fake request success");
        }

        drop(session);
        let (sr, hmac_sr) = maybe_srh.unwrap();
        tracing::debug!("Authorized, ServerRandom extracted: {sr:?}");
        let hmac_sr_s = Hmac::new(&self.password, (&sr, b"S"));
        let hmac_sr_c = Hmac::new(&self.password, (&sr, b"C"));

        verified_relay(in_stream, stream, hmac_sr_c, hmac_sr_s, Some(hmac_sr)).await;
        Ok(())
    }

    /// Connect remote, do handshaking and calculate HMAC.
    ///
    /// Only used by V2 protocol.
    async fn connect_v2(
        &self,
    ) -> anyhow::Result<(
        TcpStream,
        [u8; 20],
        rustls_fork_shadow_tls::ClientConnection,
    )>
    where
        TA: std::net::ToSocketAddrs,
    {
        let mut stream = TcpStream::connect(self.target_addr.as_ref()).await?;
        mod_tcp_conn(&mut stream, true, self.nodelay);
        tracing::debug!("tcp connected, start handshaking");
        let stream = HashedReadStream::new(stream, self.password.as_bytes())?;
        let sni = self.tls_names.random_choose().clone();
        let tls_stream = self.tls_connector.connect(sni, stream).await?;
        let (io, session) = tls_stream.into_parts();
        let hash = io.hash();
        tracing::debug!("tls handshake finished, signed hmac: {:?}", hash);
        let stream = io.into_inner();
        Ok((stream, hash, session))
    }
}

/// A wrapper for doing data extraction and modification.
///
/// Only used by V3 protocol.
struct StreamWrapper<S> {
    raw: S,
    password: String,

    read_buf: Option<Vec<u8>>,
    read_pos: usize,

    read_state: Option<State>,
    read_authorized: bool,
}

#[derive(Clone)]
struct State {
    server_random: [u8; TLS_RANDOM_SIZE],
    hmac: Hmac,
    key: Vec<u8>,
}

impl<S> StreamWrapper<S> {
    fn new(raw: S, password: &str) -> Self {
        Self {
            raw,
            password: password.to_string(),

            read_buf: Some(Vec::new()),
            read_pos: 0,

            read_state: None,
            read_authorized: false,
        }
    }

    fn authorized(&self) -> bool {
        self.read_authorized
    }

    fn state(&self) -> &Option<State> {
        &self.read_state
    }

    fn into_inner(self) -> S {
        self.raw
    }
}

impl<S: AsyncReadRent> StreamWrapper<S> {
    async fn feed_data(&mut self) -> std::io::Result<usize> {
        let mut buf = self.read_buf.take().unwrap();

        // read header
        unsafe { buf.set_init(0) };
        self.read_pos = 0;
        buf.reserve(TLS_HEADER_SIZE);
        let (res, buf) = self.raw.read_exact(buf.slice_mut(0..TLS_HEADER_SIZE)).await;
        match res {
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::debug!("stream wrapper eof");
                self.read_buf = Some(buf.into_inner());
                return Ok(0);
            }
            Err(e) => {
                tracing::error!("stream wrapper unable to read tls header: {e}");
                self.read_buf = Some(buf.into_inner());
                return Err(e);
            }
        }
        let mut buf: Vec<u8> = buf.into_inner();
        let mut size: [u8; 2] = Default::default();
        size.copy_from_slice(&buf[3..5]);
        let data_size = u16::from_be_bytes(size) as usize;

        // read body
        buf.reserve(data_size);
        let (res, buf) = self
            .raw
            .read_exact(buf.slice_mut(TLS_HEADER_SIZE..TLS_HEADER_SIZE + data_size))
            .await;
        if let Err(e) = res {
            self.read_buf = Some(buf.into_inner());
            return Err(e);
        }
        let mut buf: Vec<u8> = buf.into_inner();

        // do extraction and modification
        match buf[0] {
            HANDSHAKE => {
                if buf.len() > SERVER_RANDOM_IDX + TLS_RANDOM_SIZE && buf[5] == SERVER_HELLO {
                    // we can read server random
                    let mut server_random = [0; TLS_RANDOM_SIZE];
                    unsafe {
                        copy_nonoverlapping(
                            buf.as_ptr().add(SERVER_RANDOM_IDX),
                            server_random.as_mut_ptr(),
                            TLS_RANDOM_SIZE,
                        )
                    }
                    tracing::debug!("ServerRandom extracted: {server_random:?}");
                    let hmac = Hmac::new(&self.password, (&server_random, &[]));
                    let key = kdf(&self.password, &server_random);
                    self.read_state = Some(State {
                        server_random,
                        hmac,
                        key,
                    });
                }
            }
            APPLICATION_DATA => {
                self.read_authorized = false;
                if buf.len() > TLS_HMAC_HEADER_SIZE {
                    if let Some(State { hmac, key, .. }) = self.read_state.as_mut() {
                        hmac.update(&buf[TLS_HMAC_HEADER_SIZE..]);
                        if hmac.finalize() == buf[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE] {
                            xor_slice(&mut buf[TLS_HMAC_HEADER_SIZE..], key);
                            unsafe {
                                copy(
                                    buf.as_ptr().add(TLS_HMAC_HEADER_SIZE),
                                    buf.as_mut_ptr().add(5),
                                    buf.len() - 9,
                                )
                            };
                            (&mut buf[3..5])
                                .write_u16::<BigEndian>(data_size as u16 - HMAC_SIZE as u16)
                                .unwrap();
                            unsafe { buf.set_init(buf.len() - HMAC_SIZE) };
                            self.read_authorized = true;
                        } else {
                            tracing::debug!("app data verification failed");
                        }
                    }
                }
            }
            _ => {}
        }

        // set buffer
        let buf_len = buf.len();
        self.read_buf = Some(buf);
        Ok(buf_len)
    }
}

impl<S: AsyncWriteRent> AsyncWriteRent for StreamWrapper<S> {
    type WriteFuture<'a, T> = S::WriteFuture<'a, T> where
    T: monoio::buf::IoBuf + 'a, Self: 'a;
    type WritevFuture<'a, T>= S::WritevFuture<'a, T> where
    T: monoio::buf::IoVecBuf + 'a, Self: 'a;
    type FlushFuture<'a> = S::FlushFuture<'a> where Self: 'a;
    type ShutdownFuture<'a> = S::ShutdownFuture<'a> where Self: 'a;

    fn write<T: monoio::buf::IoBuf>(&mut self, buf: T) -> Self::WriteFuture<'_, T> {
        self.raw.write(buf)
    }
    fn writev<T: monoio::buf::IoVecBuf>(&mut self, buf_vec: T) -> Self::WritevFuture<'_, T> {
        self.raw.writev(buf_vec)
    }
    fn flush(&mut self) -> Self::FlushFuture<'_> {
        self.raw.flush()
    }
    fn shutdown(&mut self) -> Self::ShutdownFuture<'_> {
        self.raw.shutdown()
    }
}

impl<S: AsyncReadRent> AsyncReadRent for StreamWrapper<S> {
    type ReadFuture<'a, B> = impl std::future::Future<Output = monoio::BufResult<usize, B>> +'a where
        B: monoio::buf::IoBufMut + 'a, S: 'a;
    type ReadvFuture<'a, B> = impl std::future::Future<Output = monoio::BufResult<usize, B>> +'a where
        B: monoio::buf::IoVecBufMut + 'a, S: 'a;

    // uncancelable
    fn read<T: monoio::buf::IoBufMut>(&mut self, mut buf: T) -> Self::ReadFuture<'_, T> {
        async move {
            loop {
                let owned_buf = self.read_buf.as_mut().unwrap();
                let data_len = owned_buf.len() - self.read_pos;
                // there is enough data to copy
                if data_len > 0 {
                    let to_copy = buf.bytes_total().min(data_len);
                    unsafe {
                        copy_nonoverlapping(
                            owned_buf.as_ptr().add(self.read_pos),
                            buf.write_ptr(),
                            to_copy,
                        );
                        buf.set_init(to_copy);
                    };
                    self.read_pos += to_copy;
                    return (Ok(to_copy), buf);
                }

                // no data now
                match self.feed_data().await {
                    Ok(0) => return (Ok(0), buf),
                    Ok(_) => continue,
                    Err(e) => return (Err(e), buf),
                }
            }
        }
    }

    fn readv<T: monoio::buf::IoVecBufMut>(&mut self, mut buf: T) -> Self::ReadvFuture<'_, T> {
        async move {
            let slice = match monoio::buf::IoVecWrapperMut::new(buf) {
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
}

/// Doing fake request.
///
/// Only used by V3 protocol.
async fn fake_request(
    mut stream: monoio_rustls_fork_shadow_tls::ClientTlsStream<TcpStream>,
) -> std::io::Result<()> {
    const HEADER: &[u8; 207] = b"GET / HTTP/1.1\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36\nAccept: gzip, deflate, br\nConnection: Close\nCookie: sessionid=";
    let cnt =
        rand::thread_rng().gen_range(FAKE_REQUEST_LENGTH_RANGE.0..FAKE_REQUEST_LENGTH_RANGE.1);
    let mut buffer = Vec::with_capacity(cnt + HEADER.len() + 1);

    buffer.extend_from_slice(HEADER);
    rand::distributions::Alphanumeric
        .sample_iter(rand::thread_rng())
        .take(cnt)
        .for_each(|c| buffer.push(c));
    buffer.push(b'\n');

    let (res, mut buf) = stream.write_all(buffer).await;
    res?;
    let _ = stream.shutdown().await;

    // read until eof
    loop {
        let (res, b) = stream.read(buf).await;
        buf = b;
        if res? == 0 {
            return Ok(());
        }
    }
}

/// Take a slice of tls frame[5..] and returns signed session id.
///
/// Only used by V3 protocol.
fn generate_session_id(hmac: &Hmac, buf: &[u8]) -> [u8; TLS_SESSION_ID_SIZE] {
    /// Note: SESSION_ID_START does not include 5 TLS_HEADER_SIZE.
    const SESSION_ID_START: usize = 1 + 3 + 2 + TLS_RANDOM_SIZE + 1;

    if buf.len() < SESSION_ID_START + TLS_SESSION_ID_SIZE {
        tracing::warn!("unexpected client hello length");
        return [0; TLS_SESSION_ID_SIZE];
    }

    let mut session_id = [0; TLS_SESSION_ID_SIZE];
    rand::thread_rng().fill(&mut session_id[..TLS_SESSION_ID_SIZE - HMAC_SIZE]);
    let mut hmac = hmac.to_owned();
    hmac.update(&buf[0..SESSION_ID_START]);
    hmac.update(&session_id);
    hmac.update(&buf[SESSION_ID_START + TLS_SESSION_ID_SIZE..]);
    let hmac_val = hmac.finalize();
    unsafe {
        copy_nonoverlapping(
            hmac_val.as_ptr(),
            session_id.as_mut_ptr().add(TLS_SESSION_ID_SIZE - HMAC_SIZE),
            HMAC_SIZE,
        )
    }
    tracing::debug!("ClientHello before sign: {buf:?}, session_id {session_id:?}");
    session_id
}
