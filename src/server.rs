use std::{
    borrow::Cow,
    collections::VecDeque,
    ptr::{copy, copy_nonoverlapping},
    rc::Rc,
    sync::Arc,
};

use anyhow::bail;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use local_sync::oneshot::Sender;
use monoio::{
    buf::{IoBuf, IoBufMut, Slice, SliceMut},
    io::{
        AsyncReadRent, AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt, PrefixedReadIo,
        Splitable,
    },
    net::TcpStream,
};
use serde::Deserialize;
use std::net::SocketAddr;
use ppp::v2;

use crate::{
    helper_v2::{
        copy_with_application_data, copy_without_application_data, ErrGroup, FirstRetGroup,
        FutureOrOutput, HashedWriteStream, HmacHandler, HMAC_SIZE_V2,
    },
    util::{
        bind_with_pretty_error, copy_bidirectional, copy_until_eof, kdf, mod_tcp_conn, prelude::*,
        resolve, support_tls13, verified_relay, xor_slice, CursorExt, Hmac, V3Mode,
    },
    WildcardSNI,
};

/// ShadowTlsServer.
#[derive(Clone)]
pub struct ShadowTlsServer {
    listen_addr: Arc<String>,
    target_addr: Arc<String>,
    tls_addr: Arc<TlsAddrs>,
    password: Arc<String>,
    nodelay: bool,
    fastopen: bool,
    v3: V3Mode,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct TlsAddrs {
    dispatch: rustc_hash::FxHashMap<String, String>,
    fallback: String,
    wildcard_sni: WildcardSNI,
}

impl TlsAddrs {
    fn find<'a>(&'a self, key: Option<&str>, auth: bool) -> Cow<'a, str> {
        match key {
            Some(k) => match self.dispatch.get(k) {
                Some(v) => Cow::Borrowed(v),
                None => match self.wildcard_sni {
                    WildcardSNI::Authed if auth => Cow::Owned(format!("{k}:443")),
                    WildcardSNI::All => Cow::Owned(format!("{k}:443")),
                    _ => Cow::Borrowed(&self.fallback),
                },
            },
            None => Cow::Borrowed(&self.fallback),
        }
    }

    fn is_empty(&self) -> bool {
        self.dispatch.is_empty()
    }

    pub fn set_wildcard_sni(&mut self, wildcard_sni: WildcardSNI) {
        self.wildcard_sni = wildcard_sni;
    }
}

impl TryFrom<&str> for TlsAddrs {
    type Error = anyhow::Error;

    fn try_from(arg: &str) -> Result<Self, Self::Error> {
        let mut rev_parts = arg.split(';').rev();
        let fallback = rev_parts
            .next()
            .and_then(|x| if x.trim().is_empty() { None } else { Some(x) })
            .ok_or_else(|| anyhow::anyhow!("empty server addrs"))?;
        let fallback = if !fallback.contains(':') {
            format!("{fallback}:443")
        } else {
            fallback.to_string()
        };

        let mut dispatch = rustc_hash::FxHashMap::default();
        for p in rev_parts {
            let mut p = p.trim().split(':').rev();
            let mut port = Cow::<'static, str>::Borrowed("443");
            let maybe_port = p
                .next()
                .ok_or_else(|| anyhow::anyhow!("empty part found in server addrs"))?;
            let host = if maybe_port.parse::<u16>().is_ok() {
                // there is a port at the end
                port = maybe_port.into();
                p.next()
                    .ok_or_else(|| anyhow::anyhow!("no host found in server addrs part"))?
            } else {
                maybe_port
            };
            let key = match p.next() {
                Some(key) => key,
                None => host,
            };
            if p.next().is_some() {
                bail!("unrecognized server addrs part");
            }
            if dispatch
                .insert(key.to_string(), format!("{host}:{port}"))
                .is_some()
            {
                bail!("duplicate server addrs part found");
            }
        }
        Ok(TlsAddrs {
            dispatch,
            fallback,
            wildcard_sni: Default::default(),
        })
    }
}

impl std::fmt::Display for TlsAddrs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(wildcard-sni:{})", self.wildcard_sni)?;
        for (k, v) in self.dispatch.iter() {
            write!(f, "{k}->{v};")?;
        }
        write!(f, "fallback->{}", self.fallback)
    }
}

impl ShadowTlsServer {
    pub fn new(
        listen_addr: String,
        target_addr: String,
        tls_addr: TlsAddrs,
        password: String,
        nodelay: bool,
        fastopen: bool,
        v3: V3Mode,
    ) -> Self {
        Self {
            listen_addr: Arc::new(listen_addr),
            target_addr: Arc::new(target_addr),
            tls_addr: Arc::new(tls_addr),
            password: Arc::new(password),
            nodelay,
            fastopen,
            v3,
        }
    }
}

impl ShadowTlsServer {
    /// Serve a raw connection.
    pub async fn serve(self) -> anyhow::Result<()> {
        let listener = bind_with_pretty_error(self.listen_addr.as_ref(), self.fastopen)?;
        let shared = Rc::new(self);
        loop {
            match listener.accept().await {
                Ok((mut conn, addr)) => {
                    tracing::info!("Accepted a connection from {addr}");
                    let server = shared.clone();
                    mod_tcp_conn(&mut conn, true, shared.nodelay);
                    monoio::spawn(async move {
                        let _ = match server.v3.enabled() {
                            false => server.relay_v2(conn).await,
                            true => server.relay_v3(conn).await,
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
    async fn relay_v2(&self, in_stream: TcpStream) -> anyhow::Result<()> {
        // wrap in_stream with hash layer
        let mut in_stream = HashedWriteStream::new(in_stream, self.password.as_bytes())?;
        let mut hmac = in_stream.hmac_handler();

        // read and extract server name
        // if there is only one fallback server, skip it
        let (prefix, server_name) = match self.tls_addr.is_empty() {
            true => (Vec::new(), None),
            false => extract_sni_v2(&mut in_stream).await?,
        };
        let prefixed_io = PrefixedReadIo::new(&mut in_stream, std::io::Cursor::new(prefix));
        tracing::debug!("server name extracted from SNI extention: {server_name:?}");

        // choose handshake server addr and connect
        let server_name = server_name.and_then(|s| String::from_utf8(s).ok());
        let addr = resolve(
            &self
                .tls_addr
                .find(server_name.as_ref().map(AsRef::as_ref), true),
        )
        .await?;
        let mut out_stream = TcpStream::connect_addr(addr).await?;
        mod_tcp_conn(&mut out_stream, true, self.nodelay);
        tracing::debug!("handshake server connected: {addr}");

        // copy stage 1
        let (mut out_r, mut out_w) = out_stream.into_split();
        let (mut in_r, mut in_w) = prefixed_io.into_split();
        let (switch, cp) = FirstRetGroup::new(
            copy_until_handshake_finished(&mut in_r, &mut out_w, &hmac),
            Box::pin(copy_until_eof(&mut out_r, &mut in_w)),
        )
        .await?;
        hmac.disable();
        tracing::debug!("handshake finished, switch: {switch:?}");

        // copy stage 2
        match switch {
            SwitchResult::Switch(data_left) => {
                drop(cp);
                let in_stream = unsafe { in_r.reunite(in_w).unwrap_unchecked() };
                let in_stream = in_stream.into_inner();
                let (mut in_r, mut in_w) = in_stream.into_split();

                // connect our data server
                let _ = out_r.reunite(out_w).unwrap().shutdown().await;
                let mut data_stream =
                    TcpStream::connect_addr(resolve(&self.target_addr).await?).await?;
                mod_tcp_conn(&mut data_stream, true, self.nodelay);
                tracing::debug!("data server connected, start relay");
                let (mut data_r, mut data_w) = data_stream.into_split();
                let (result, _) = data_w.write(data_left).await;
                result?;
                ErrGroup::new(
                    copy_with_application_data::<0, _, _>(&mut data_r, &mut in_w, None),
                    copy_without_application_data(&mut in_r, &mut data_w),
                )
                .await?;
            }
            SwitchResult::DirectProxy => match cp {
                FutureOrOutput::Future(cp) => {
                    ErrGroup::new(cp, copy_until_eof(in_r, out_w)).await?;
                }
                FutureOrOutput::Output(_) => {
                    copy_until_eof(in_r, out_w).await?;
                }
            },
        }
        Ok(())
    }

    /// Main relay for V3 protocol.
    async fn relay_v3(&self, mut in_stream: TcpStream) -> anyhow::Result<()> {
        // stage 1.1: read and validate client hello
        let first_client_frame = read_exact_frame(&mut in_stream).await?;
        let (client_hello_pass, sni) = verified_extract_sni(&first_client_frame, &self.password);

        // connect handshake server
        let server_name = sni.and_then(|s| String::from_utf8(s).ok());
        let addr = resolve(
            &self
                .tls_addr
                .find(server_name.as_ref().map(AsRef::as_ref), client_hello_pass),
        )
        .await?;
        let mut handshake_stream = TcpStream::connect_addr(addr).await?;
        mod_tcp_conn(&mut handshake_stream, true, self.nodelay);
        tracing::debug!("handshake server connected: {addr}");
        tracing::trace!("ClientHello frame {first_client_frame:?}");
        let (res, _) = handshake_stream.write_all(first_client_frame).await;
        res?;
        if !client_hello_pass {
            // if client verify failed, bidirectional copy and return
            tracing::warn!("ClientHello verify failed, will work as a SNI proxy");
            copy_bidirectional(in_stream, handshake_stream).await;
            return Ok(());
        }
        tracing::debug!("ClientHello verify success");

        // stage 1.2: read server hello and extract server random from it
        let first_server_frame = read_exact_frame(&mut handshake_stream).await?;
        let (res, first_server_frame) = in_stream.write_all(first_server_frame).await;
        res?;
        let server_random = match extract_server_random(&first_server_frame) {
            Some(sr) => sr,
            None => {
                // we cannot extract server random, bidirectional copy and return
                tracing::warn!("ServerRandom extract failed, will copy bidirectional");
                copy_bidirectional(in_stream, handshake_stream).await;
                return Ok(());
            }
        };
        tracing::debug!("Client authenticated. ServerRandom extracted: {server_random:?}");

        let use_tls13 = support_tls13(&first_server_frame);
        if self.v3.strict() && !use_tls13 {
            tracing::error!(
                "V3 strict enabled and TLS 1.3 is not supported, will copy bidirectional"
            );
            copy_bidirectional(in_stream, handshake_stream).await;
            return Ok(());
        }

        // stage 1.3.1: create HMAC_ServerRandomC and HMAC_ServerRandom
        let mut hmac_sr_c = Hmac::new(&self.password, (&server_random, b"C"));
        let hmac_sr_s = Hmac::new(&self.password, (&server_random, b"S"));
        let mut hmac_sr = Hmac::new(&self.password, (&server_random, &[]));

        let client_address = in_stream.peer_addr()?; // Get the client's IP address
        let server_address = resolve(&self.target_addr).await?; // Server address to connect to

        let header = v2::Builder::with_addresses(
            v2::Version::Two | v2::Command::Proxy,
            v2::Protocol::Stream,
            (client_address, server_address),
        )
        .build()
        .unwrap();

        // stage 1.3.2: copy ShadowTLS Client -> Handshake Server until hamc matches
        // stage 1.3.3: copy and modify Handshake Server -> ShadowTLS Client until 1.3.2 stops
        let (mut c_read, mut c_write) = in_stream.into_split();
        let pure_data = {
            let (mut h_read, mut h_write) = handshake_stream.into_split();
            let (mut sender, mut recevier) = local_sync::oneshot::channel::<()>();
            let key = kdf(&self.password, &server_random);
            let (maybe_pure, _) = monoio::join!(
                async {
                    let r =
                        copy_by_frame_until_hmac_matches(&mut c_read, &mut h_write, &mut hmac_sr_c)
                            .await;
                    recevier.close();
                    if r.is_err() {
                        let _ = h_write.shutdown().await;
                    }
                    r
                },
                async {
                    let r = copy_by_frame_with_modification(
                        &mut h_read,
                        &mut c_write,
                        &mut hmac_sr,
                        &key,
                        &mut sender,
                    )
                    .await;
                    if r.is_err() {
                        let _ = c_write.shutdown().await;
                    }
                }
            );
            maybe_pure?
        };
        tracing::debug!("handshake relay finished");

        // early drop useless resources
        drop(first_server_frame);

        // stage 2.2: copy ShadowTLS Client -> Data Server
        // stage 2.3: copy Data Server -> ShadowTLS Client
        let mut data_stream = TcpStream::connect_addr(resolve(&self.target_addr).await?).await?;
        mod_tcp_conn(&mut data_stream, true, self.nodelay);
        // 发送 Proxy Protocol v2 头部到目标服务器
        let (res, _) = data_stream.write_all(header).await;
        res?; // 检查是否成功发送

        let (res, _) = data_stream.write_all(pure_data).await;
        res?;
        verified_relay(
            data_stream,
            unsafe { c_read.reunite(c_write).unwrap_unchecked() },
            hmac_sr_s,
            hmac_sr_c,
            None,
            !use_tls13,
        )
        .await;
        Ok(())
    }
}

/// A helper struct for doing source switching.
///
/// Only used by V2 protocol.
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

/// Copy until handshake finished.
/// We use HMAC to check if handshake finished.
///
/// Only used by V2 protocol.
async fn copy_until_handshake_finished<R, W>(
    mut read_half: R,
    mut write_half: W,
    hmac: &HmacHandler,
) -> std::io::Result<SwitchResult>
where
    R: AsyncReadRent,
    W: AsyncWriteRent,
{
    // We maintain 2 state to make sure current session is in an tls session.
    // This is essential for preventing active detection.
    let mut has_seen_change_cipher_spec = false;
    let mut has_seen_handshake = false;

    // header_buf is used to read handshake frame header, will be a fixed size buffer.
    let mut header_buf = vec![0_u8; TLS_HEADER_SIZE].into_boxed_slice();
    let mut header_read_len = 0;
    let mut header_write_len = 0;
    // data_buf is used to read and write data, and can be expanded.
    let mut data_hmac_buf = vec![0_u8; HMAC_SIZE_V2].into_boxed_slice();
    let mut data_buf = vec![0_u8; 2048];
    let mut application_data_count: usize = 0;

    let mut hashes = VecDeque::with_capacity(10);
    loop {
        let header_buf_slice = SliceMut::new(header_buf, header_read_len, TLS_HEADER_SIZE);
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

        if header_read_len != TLS_HEADER_SIZE {
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
            || data_size < HMAC_SIZE_V2
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
        while hmac_read_len < HMAC_SIZE_V2 {
            let buf = SliceMut::new(data_hmac_buf, hmac_read_len, HMAC_SIZE_V2);
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
        let mut hash_trim = [0; HMAC_SIZE_V2];
        unsafe { copy_nonoverlapping(hash.as_ptr(), hash_trim.as_mut_ptr(), HMAC_SIZE_V2) };
        tracing::debug!("hmac calculated: {hash_trim:?}");
        if hashes.len() + 1 > hashes.capacity() {
            hashes.pop_front();
        }
        hashes.push_back(hash_trim);
        unsafe {
            copy_nonoverlapping(data_hmac_buf.as_ptr(), hash_trim.as_mut_ptr(), HMAC_SIZE_V2)
        };
        if hashes.contains(&hash_trim) {
            tracing::debug!("hmac matches");
            let pure_data = vec![0; data_size - HMAC_SIZE_V2];
            let (read_res, pure_data) = read_half.read_exact(pure_data).await;
            read_res?;
            return Ok(SwitchResult::Switch(pure_data));
        }

        // Now hmac does not match. We have to acc the counter and do copy.
        application_data_count += 1;
        let mut to_copy = data_size - HMAC_SIZE_V2;
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

/// Read from connection and parse the frame.
/// Return consumed data and SNI.
///
/// Only used by V2 protocol.
async fn extract_sni_v2<R: AsyncReadRent>(mut r: R) -> std::io::Result<(Vec<u8>, Option<Vec<u8>>)> {
    macro_rules! read_ok {
        ($res: expr, $data: expr) => {
            match $res {
                Ok(r) => r,
                Err(_) => {
                    return Ok(($data, None));
                }
            }
        };
    }

    let header = vec![0; TLS_HEADER_SIZE];
    let (res, header) = r.read_exact(header).await;
    res?;

    // validate header and fail fast
    if header[0] != HANDSHAKE
        || header[1] != TLS_MAJOR
        || (header[2] != TLS_MINOR.0 && header[2] != TLS_MINOR.1)
    {
        return Ok((header, None));
    }

    // read tls frame length
    let mut size: [u8; 2] = Default::default();
    size.copy_from_slice(&header[3..5]);
    let data_size = u16::from_be_bytes(size);
    tracing::debug!("read handshake length {}", data_size);

    // read tls frame
    let mut data = vec![0; data_size as usize + TLS_HEADER_SIZE];
    unsafe { copy_nonoverlapping(header.as_ptr(), data.as_mut_ptr(), TLS_HEADER_SIZE) };
    let (res, data_slice) = r.read_exact(data.slice_mut(TLS_HEADER_SIZE..)).await;
    res?;

    // validate client hello
    let data_slice: SliceMut<Vec<u8>> = data_slice;
    let data = data_slice.into_inner();
    let mut cursor = std::io::Cursor::new(&data[TLS_HEADER_SIZE..]);
    if read_ok!(cursor.read_u8(), data) != CLIENT_HELLO {
        tracing::debug!("first packet is not client hello");
        return Ok((data, None));
    }
    // length[0] must be 0
    if read_ok!(cursor.read_u8(), data) != 0 {
        tracing::debug!("client hello length first byte is not zero");
        return Ok((data, None));
    }
    // client hello length[1..=2]
    let prot_size = read_ok!(cursor.read_u16::<BigEndian>(), data);
    if prot_size + 4 > data_size {
        tracing::debug!("invalid client hello length");
        return Ok((data, None));
    }
    // reset cursor with new smaller length limit
    let mut cursor = std::io::Cursor::new(
        &data[TLS_HMAC_HEADER_SIZE..TLS_HMAC_HEADER_SIZE + prot_size as usize],
    );
    // skip 2 byte version
    read_ok!(cursor.read_u16::<BigEndian>(), data);
    // skip 32 byte random
    read_ok!(cursor.skip(TLS_RANDOM_SIZE), data);
    // skip session id
    read_ok!(cursor.skip_by_u8(), data);
    // skip cipher suites
    read_ok!(cursor.skip_by_u16(), data);
    // skip compression method
    read_ok!(cursor.skip_by_u8(), data);
    // skip ext length
    read_ok!(cursor.read_u16::<BigEndian>(), data);

    loop {
        let ext_type = read_ok!(cursor.read_u16::<BigEndian>(), data);
        if ext_type != SNI_EXT_TYPE {
            read_ok!(cursor.skip_by_u16(), data);
            continue;
        }
        tracing::debug!("found server_name extension");
        let _ext_len = read_ok!(cursor.read_u16::<BigEndian>(), data);
        let _sni_len = read_ok!(cursor.read_u16::<BigEndian>(), data);
        // must be host_name
        if read_ok!(cursor.read_u8(), data) != 0 {
            return Ok((data, None));
        }
        let sni = Some(read_ok!(cursor.read_by_u16(), data));
        return Ok((data, sni));
    }
}

/// Read a single frame and return Vec.
///
/// Only used by V3 protocol.
async fn read_exact_frame(r: impl AsyncReadRent) -> std::io::Result<Vec<u8>> {
    read_exact_frame_into(r, Vec::new()).await
}

/// Read a single frame into given Vec.
///
/// Only used by V3 protocol.
async fn read_exact_frame_into(
    mut r: impl AsyncReadRent,
    mut buffer: Vec<u8>,
) -> std::io::Result<Vec<u8>> {
    unsafe { buffer.set_len(0) };
    buffer.reserve(TLS_HEADER_SIZE);
    let (res, header) = r.read_exact(buffer.slice_mut(..TLS_HEADER_SIZE)).await;
    res?;
    let mut buffer = header.into_inner();

    // read tls frame length
    let mut size: [u8; 2] = Default::default();
    size.copy_from_slice(&buffer[3..5]);
    let data_size = u16::from_be_bytes(size) as usize;

    // read tls frame body
    buffer.reserve(data_size);
    let (res, data_slice) = r
        .read_exact(buffer.slice_mut(TLS_HEADER_SIZE..TLS_HEADER_SIZE + data_size))
        .await;
    res?;

    Ok(data_slice.into_inner())
}

/// Parse frame, verify it and extract SNI.
/// Return is_pass and Option<SNI>.
/// It requires &mut but it is meant for doing operation inplace.
/// It does not modify the data.
///
/// Only used by V3 protocol.
fn verified_extract_sni(frame: &[u8], password: &str) -> (bool, Option<Vec<u8>>) {
    // 5 frame header + 1 handshake type + 3 length + 2 version + 32 random + 1 session id len + 32 session id
    const MIN_LEN: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE + 1 + TLS_SESSION_ID_SIZE;
    const HMAC_IDX: usize = SESSION_ID_LEN_IDX + 1 + TLS_SESSION_ID_SIZE - HMAC_SIZE;
    const ZERO4B: [u8; HMAC_SIZE] = [0; HMAC_SIZE];

    if frame.len() < SESSION_ID_LEN_IDX || frame[0] != HANDSHAKE || frame[5] != CLIENT_HELLO {
        return (false, None);
    }

    let pass = if frame.len() < MIN_LEN || frame[SESSION_ID_LEN_IDX] != TLS_SESSION_ID_SIZE as u8 {
        false
    } else {
        let mut hmac = Hmac::new(password, (&[], &[]));
        hmac.update(&frame[TLS_HEADER_SIZE..HMAC_IDX]);
        hmac.update(&ZERO4B);
        hmac.update(&frame[HMAC_IDX + HMAC_SIZE..]);
        hmac.finalize() == frame[HMAC_IDX..HMAC_IDX + HMAC_SIZE]
    };

    let mut cursor = std::io::Cursor::new(&frame[SESSION_ID_LEN_IDX..]);
    macro_rules! read_ok {
        ($res: expr) => {
            match $res {
                Ok(r) => r,
                Err(_) => {
                    return (pass, None);
                }
            }
        };
    }

    // skip session id
    read_ok!(cursor.skip_by_u8());
    // skip cipher suites
    read_ok!(cursor.skip_by_u16());
    // skip compression method
    read_ok!(cursor.skip_by_u8());
    // skip ext length
    read_ok!(cursor.read_u16::<BigEndian>());

    loop {
        let ext_type = read_ok!(cursor.read_u16::<BigEndian>());
        if ext_type != SNI_EXT_TYPE {
            read_ok!(cursor.skip_by_u16());
            continue;
        }
        tracing::debug!("found server_name extension");
        let _ext_len = read_ok!(cursor.read_u16::<BigEndian>());
        let _sni_len = read_ok!(cursor.read_u16::<BigEndian>());
        // must be host_name
        if read_ok!(cursor.read_u8()) != 0 {
            return (pass, None);
        }
        let sni = Some(read_ok!(cursor.read_by_u16()));
        return (pass, sni);
    }
}

/// Parse given frame and extract ServerRandom.
/// Return Option<ServerRandom>.
///
/// Only used by V3 protocol.
fn extract_server_random(frame: &[u8]) -> Option<[u8; TLS_RANDOM_SIZE]> {
    // 5 frame header + 1 handshake type + 3 length + 2 version + 32 random
    const MIN_LEN: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;

    if frame.len() < MIN_LEN || frame[0] != HANDSHAKE || frame[5] != SERVER_HELLO {
        return None;
    }

    let mut server_random = [0; TLS_RANDOM_SIZE];
    unsafe {
        copy_nonoverlapping(
            frame.as_ptr().add(SERVER_RANDOM_IDX),
            server_random.as_mut_ptr(),
            TLS_RANDOM_SIZE,
        )
    };

    Some(server_random)
}

/// Copy frame by frame until a appdata frame matches hmac.
/// Return the matched pure data(without header).
///
/// Only used by V3 protocol.
async fn copy_by_frame_until_hmac_matches(
    mut read: impl AsyncReadRent,
    mut write: impl AsyncWriteRent,
    hmac: &mut Hmac,
) -> std::io::Result<Vec<u8>> {
    let mut g_buffer = Vec::new();

    loop {
        let buffer = read_exact_frame_into(&mut read, g_buffer).await?;
        if buffer.len() > 9 && buffer[0] == APPLICATION_DATA {
            // check hmac
            let mut tmp_hmac = hmac.to_owned();
            tmp_hmac.update(&buffer[TLS_HMAC_HEADER_SIZE..]);
            let h = tmp_hmac.finalize();

            if buffer[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE] == h {
                hmac.update(&buffer[TLS_HMAC_HEADER_SIZE..]);
                hmac.update(&buffer[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE]);
                return Ok(buffer[TLS_HMAC_HEADER_SIZE..].to_vec());
            }
        }

        let (res, buffer) = write.write_all(buffer).await;
        res?;
        g_buffer = buffer;
    }
}

/// Copy frame by frame.
/// Modify appdata frame:
/// 1. Cycle XOR xor data.
/// 2. Calculate HMAC and insert before the frame data.
///
/// Only used by V3 protocol.
async fn copy_by_frame_with_modification(
    mut read: impl AsyncReadRent,
    mut write: impl AsyncWriteRent,
    hmac: &mut Hmac,
    xor: &[u8],
    stop: &mut Sender<()>,
) -> std::io::Result<()> {
    let mut g_buffer = Vec::new();
    let stop = stop.closed();
    let mut stop = std::pin::pin!(stop);

    loop {
        monoio::select! {
            // this function can be stopped by a channel when reading.
            _ = &mut stop => {
                return Ok(());
            },
            buffer_res = read_exact_frame_into(&mut read, g_buffer) => {
                let mut buffer = buffer_res?;
                // Note: if we get frame, it is guaranteed valid.
                if buffer[0] == APPLICATION_DATA {
                    // do modification: xor data, add 4-byte hmac, update tls frame length
                    xor_slice(&mut buffer[TLS_HEADER_SIZE..], xor);
                    hmac.update(&buffer[TLS_HEADER_SIZE..]);
                    let hash = hmac.finalize();
                    buffer.extend_from_slice(&hash);
                    unsafe {
                        copy(buffer.as_ptr().add(TLS_HEADER_SIZE), buffer.as_mut_ptr().add(TLS_HMAC_HEADER_SIZE), buffer.len() - TLS_HMAC_HEADER_SIZE);
                        copy_nonoverlapping(hash.as_ptr(), buffer.as_mut_ptr().add(TLS_HEADER_SIZE), HMAC_SIZE);
                    }

                    let mut size: [u8; 2] = Default::default();
                    size.copy_from_slice(&buffer[3..5]);
                    let data_size = u16::from_be_bytes(size);
                    // Normally it does not overflow.
                    let data_size = data_size.wrapping_add(HMAC_SIZE as u16);
                    (&mut buffer[3..5]).write_u16::<BigEndian>(data_size).unwrap();
                }

                // writing is not cancelable
                let (res, buffer) = write.write_all(buffer).await;
                res?;
                g_buffer = buffer;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_map<K: Into<String>, V: Into<String>>(
        kvs: Vec<(K, V)>,
    ) -> rustc_hash::FxHashMap<String, String> {
        kvs.into_iter().map(|(k, v)| (k.into(), v.into())).collect()
    }

    macro_rules! map {
        [] => {rustc_hash::FxHashMap::<String, String>::default()};
        [$($k:expr => $v:expr),*] => {to_map(vec![$(($k.to_owned(), $v.to_owned())), *])};
        [$($k:expr => $v:expr,)*] => {to_map(vec![$(($k.to_owned(), $v.to_owned())), *])};
    }

    macro_rules! s {
        ($v:expr) => {
            $v.to_string()
        };
    }

    #[test]
    fn parse_tls_addrs() {
        assert_eq!(
            TlsAddrs::try_from("google.com").unwrap(),
            TlsAddrs {
                dispatch: map![],
                fallback: s!("google.com:443"),
                wildcard_sni: Default::default(),
            }
        );
        assert_eq!(
            TlsAddrs::try_from("feishu.cn;cloudflare.com:1.1.1.1:80;google.com").unwrap(),
            TlsAddrs {
                dispatch: map![
                    "feishu.cn" => "feishu.cn:443",
                    "cloudflare.com" => "1.1.1.1:80",
                ],
                fallback: s!("google.com:443"),
                wildcard_sni: Default::default(),
            }
        );
        assert_eq!(
            TlsAddrs::try_from("captive.apple.com;feishu.cn:80").unwrap(),
            TlsAddrs {
                dispatch: map![
                    "captive.apple.com" => "captive.apple.com:443",
                ],
                fallback: s!("feishu.cn:80"),
                wildcard_sni: Default::default(),
            }
        );
    }
}
