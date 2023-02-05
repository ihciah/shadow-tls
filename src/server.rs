use std::{
    borrow::Cow, collections::VecDeque, io::Read, ptr::copy_nonoverlapping, rc::Rc, sync::Arc,
};

use anyhow::bail;
use byteorder::{BigEndian, ReadBytesExt};
use monoio::{
    buf::{IoBuf, IoBufMut, Slice, SliceMut},
    io::{
        AsyncReadRent, AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt, PrefixedReadIo,
        Splitable,
    },
    net::{TcpListener, TcpStream},
};

use crate::{
    stream::{HashedWriteStream, HmacHandler},
    util::{
        copy_until_eof, copy_with_application_data, copy_without_application_data, mod_tcp_conn,
        ErrGroup, FirstRetGroup, APPLICATION_DATA,
    },
};

const HANDSHAKE: u8 = 0x16;
const TLS_MAJOR: u8 = 0x03;
const TLS_MINOR: (u8, u8) = (0x03, 0x01);
const HEADER_BUF_SIZE: usize = 5;
const CLIENT_HELLO: u8 = 1;
const SNI_EXT_TYPE: u16 = 0;

/// ShadowTlsServer.
#[derive(Clone)]
pub struct ShadowTlsServer<LA, TA> {
    listen_addr: Arc<LA>,
    target_addr: Arc<TA>,
    tls_addr: Arc<TlsAddrs>,
    password: Arc<String>,
    nodelay: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TlsAddrs {
    dispatch: rustc_hash::FxHashMap<String, String>,
    fallback: String,
}

impl TlsAddrs {
    fn find(&self, key: Option<&str>) -> &str {
        match key {
            Some(k) => self.dispatch.get(k).unwrap_or(&self.fallback),
            None => &self.fallback,
        }
    }

    fn is_empty(&self) -> bool {
        self.dispatch.is_empty()
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
        Ok(TlsAddrs { dispatch, fallback })
    }
}

pub fn parse_server_addrs(arg: &str) -> anyhow::Result<TlsAddrs> {
    TlsAddrs::try_from(arg)
}

impl std::fmt::Display for TlsAddrs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (k, v) in self.dispatch.iter() {
            write!(f, "{k}->{v};")?;
        }
        write!(f, "fallback->{}", self.fallback)
    }
}

impl<LA, TA> ShadowTlsServer<LA, TA> {
    pub fn new(
        listen_addr: LA,
        target_addr: TA,
        tls_addr: TlsAddrs,
        password: String,
        nodelay: bool,
    ) -> Self {
        Self {
            listen_addr: Arc::new(listen_addr),
            target_addr: Arc::new(target_addr),
            tls_addr: Arc::new(tls_addr),
            password: Arc::new(password),
            nodelay,
        }
    }
}

impl<LA, TA> ShadowTlsServer<LA, TA> {
    pub async fn serve(self) -> anyhow::Result<()>
    where
        LA: std::net::ToSocketAddrs + 'static,
        TA: std::net::ToSocketAddrs + 'static,
    {
        let listener = TcpListener::bind(self.listen_addr.as_ref())
            .map_err(|e| anyhow::anyhow!("bind failed, check if the port is used: {e}"))?;
        let shared = Rc::new(self);
        loop {
            match listener.accept().await {
                Ok((mut conn, addr)) => {
                    tracing::info!("Accepted a connection from {addr}");
                    let server = shared.clone();
                    mod_tcp_conn(&mut conn, true, shared.nodelay);
                    monoio::spawn(async move {
                        let _ = server.relay(conn).await;
                        tracing::info!("Relay for {addr} finished");
                    });
                }
                Err(e) => {
                    tracing::error!("Accept failed: {e}");
                }
            }
        }
    }

    async fn relay(&self, in_stream: TcpStream) -> anyhow::Result<()>
    where
        TA: std::net::ToSocketAddrs,
    {
        // wrap in_stream with hash layer
        let mut in_stream = HashedWriteStream::new(in_stream, self.password.as_bytes())?;
        let mut hmac = in_stream.hmac_handler();

        // read and extract server name
        // if there is only one fallback server, skip it
        let (prefix, server_name) = match self.tls_addr.is_empty() {
            true => (Vec::new(), None),
            false => extract_sni(&mut in_stream).await?,
        };
        let mut prefixed_io = PrefixedReadIo::new(&mut in_stream, std::io::Cursor::new(prefix));
        tracing::debug!("server name extracted from SNI extention: {server_name:?}");

        // choose handshake server addr and connect
        let server_name = server_name.and_then(|s| String::from_utf8(s).ok());
        let addr = self.tls_addr.find(server_name.as_ref().map(AsRef::as_ref));
        let mut out_stream = TcpStream::connect(addr).await?;
        mod_tcp_conn(&mut out_stream, true, self.nodelay);
        tracing::debug!("handshake server connected: {addr}");

        // copy stage 1
        let (mut out_r, mut out_w) = out_stream.split();
        let (mut in_r, mut in_w) = prefixed_io.split();
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
                let mut in_stream = in_stream.into_inner();
                let (mut in_r, mut in_w) = in_stream.split();

                // connect our data server
                let _ = out_stream.shutdown().await;
                drop(out_stream);
                let mut data_stream = TcpStream::connect(self.target_addr.as_ref()).await?;
                mod_tcp_conn(&mut data_stream, true, self.nodelay);
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
    const CHANGE_CIPHER_SPEC: u8 = 0x14;
    // We maintain 2 state to make sure current session is in an tls session.
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

    let mut hashes = VecDeque::with_capacity(10);
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
        let mut hash_trim = [0; HMAC_SIZE];
        unsafe { copy_nonoverlapping(hash.as_ptr(), hash_trim.as_mut_ptr(), HMAC_SIZE) };
        tracing::debug!("hmac calculated: {hash_trim:?}");
        if hashes.len() + 1 > hashes.capacity() {
            hashes.pop_front();
        }
        hashes.push_back(hash_trim);
        unsafe { copy_nonoverlapping(data_hmac_buf.as_ptr(), hash_trim.as_mut_ptr(), HMAC_SIZE) };
        if hashes.contains(&hash_trim) {
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

async fn extract_sni<R: AsyncReadRent>(mut r: R) -> std::io::Result<(Vec<u8>, Option<Vec<u8>>)> {
    let header = vec![0; HEADER_BUF_SIZE];
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
    let mut data = vec![0; data_size as usize + HEADER_BUF_SIZE];
    unsafe { copy_nonoverlapping(header.as_ptr(), data.as_mut_ptr(), HEADER_BUF_SIZE) };
    let (res, data_slice) = r.read_exact(data.slice_mut(5..)).await;
    res?;

    // validate client hello
    let data_slice: SliceMut<Vec<u8>> = data_slice;
    let data = data_slice.into_inner();
    let mut cursor = std::io::Cursor::new(&data[HEADER_BUF_SIZE..]);
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
    let mut cursor =
        std::io::Cursor::new(&data[HEADER_BUF_SIZE + 4..HEADER_BUF_SIZE + 4 + prot_size as usize]);
    // skip 2 byte version
    read_ok!(cursor.read_u16::<BigEndian>(), data);
    // skip 32 byte random
    read_ok!(cursor.skip(32), data);
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
        tracing::debug!("found SNI extension");
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

trait CursorExt {
    fn read_by_u16(&mut self) -> std::io::Result<Vec<u8>>;
    fn skip(&mut self, n: usize) -> std::io::Result<()>;
    fn skip_by_u8(&mut self) -> std::io::Result<u8>;
    fn skip_by_u16(&mut self) -> std::io::Result<u16>;
}

impl<T> CursorExt for std::io::Cursor<T>
where
    std::io::Cursor<T>: std::io::Read,
{
    #[inline]
    fn read_by_u16(&mut self) -> std::io::Result<Vec<u8>> {
        let len = self.read_u16::<BigEndian>()?;
        let mut buf = vec![0; len as usize];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }

    #[inline]
    fn skip(&mut self, n: usize) -> std::io::Result<()> {
        for _ in 0..n {
            self.read_u8()?;
        }
        Ok(())
    }

    #[inline]
    fn skip_by_u8(&mut self) -> std::io::Result<u8> {
        let len = self.read_u8()?;
        self.skip(len as usize)?;
        Ok(len)
    }

    #[inline]
    fn skip_by_u16(&mut self) -> std::io::Result<u16> {
        let len = self.read_u16::<BigEndian>()?;
        self.skip(len as usize)?;
        Ok(len)
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
            parse_server_addrs("google.com").unwrap(),
            TlsAddrs {
                dispatch: map![],
                fallback: s!("google.com:443")
            }
        );
        assert_eq!(
            parse_server_addrs("feishu.cn;cloudflare.com:1.1.1.1:80;google.com").unwrap(),
            TlsAddrs {
                dispatch: map![
                    "feishu.cn" => "feishu.cn:443",
                    "cloudflare.com" => "1.1.1.1:80",
                ],
                fallback: s!("google.com:443")
            }
        );
        assert_eq!(
            parse_server_addrs("captive.apple.com;feishu.cn:80").unwrap(),
            TlsAddrs {
                dispatch: map![
                    "captive.apple.com" => "captive.apple.com:443",
                ],
                fallback: s!("feishu.cn:80")
            }
        );
    }
}
