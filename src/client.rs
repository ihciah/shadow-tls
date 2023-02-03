use std::net::SocketAddr;

use monoio::{io::Splitable, net::TcpStream};
use monoio_rustls::TlsConnector;
use rand::seq::SliceRandom;
use rustls::{OwnedTrustAnchor, RootCertStore, ServerName};

use crate::{
    stream::HashedReadStream,
    util::{copy_with_application_data, copy_without_application_data, mod_tcp_conn},
    Opts,
};

/// ShadowTlsClient.
pub struct ShadowTlsClient<A> {
    tls_connector: TlsConnector,
    server_names: Box<[ServerName]>,
    address: A,
    password: String,
    opts: Opts,
}

#[derive(Default, Debug)]
pub struct TlsExtConfig {
    alpn: Option<Vec<Vec<u8>>>,
}

impl TlsExtConfig {
    pub fn new(alpn: Option<Vec<Vec<u8>>>) -> TlsExtConfig {
        TlsExtConfig { alpn }
    }
}

impl<A> ShadowTlsClient<A> {
    /// Create new ShadowTlsClient.
    pub fn new(
        server_names: std::slice::Iter<String>,
        address: A,
        password: String,
        opts: Opts,
        tls_ext_config: TlsExtConfig,
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
        let mut tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Set tls config
        if let Some(alpn) = tls_ext_config.alpn {
            tls_config.alpn_protocols = alpn;
        }

        let tls_connector = TlsConnector::from(tls_config);
        let mut sni_list = Vec::new();
        for s in server_names {
            let sni = ServerName::try_from(s.as_str())?;
            sni_list.push(sni);
        }

        Ok(Self {
            tls_connector,
            server_names: sni_list.into_boxed_slice(),
            address,
            password,
            opts,
        })
    }

    /// Establish connection with remote and relay data.
    pub async fn relay(
        &self,
        mut in_stream: TcpStream,
        in_stream_addr: SocketAddr,
    ) -> anyhow::Result<()>
    where
        A: std::net::ToSocketAddrs,
    {
        let (mut out_stream, hash) = self.connect().await?;
        let mut hash_8b = [0; 8];
        unsafe { std::ptr::copy_nonoverlapping(hash.as_ptr(), hash_8b.as_mut_ptr(), 8) };
        let (mut out_r, mut out_w) = out_stream.split();
        let (mut in_r, mut in_w) = in_stream.split();
        let (a, b) = monoio::join!(
            copy_without_application_data(&mut out_r, &mut in_w),
            copy_with_application_data(&mut in_r, &mut out_w, Some(hash_8b))
        );
        let (_, _) = (a?, b?);
        tracing::info!("Relay for {in_stream_addr} finished");
        Ok(())
    }

    /// Connect remote, do handshaking and calculate HMAC.
    async fn connect(&self) -> anyhow::Result<(TcpStream, [u8; 20])>
    where
        A: std::net::ToSocketAddrs,
    {
        let mut stream = TcpStream::connect(&self.address).await?;
        mod_tcp_conn(&mut stream, true, !self.opts.disable_nodelay);
        tracing::debug!("tcp connected, start handshaking");
        let stream = HashedReadStream::new(stream, self.password.as_bytes())?;
        let endpoint = self
            .server_names
            .choose(&mut rand::thread_rng())
            .expect("empty endpoints set")
            .clone();
        let tls_stream = self.tls_connector.connect(endpoint, stream).await?;
        let (io, _) = tls_stream.into_parts();
        let hash = io.hash();
        tracing::debug!("tls handshake finished, signed hmac: {:?}", hash);
        let stream = io.into_inner();
        Ok((stream, hash))
    }
}

pub fn parse_client_addrs(addrs: &str) -> anyhow::Result<Vec<String>> {
    Ok(addrs
        .trim()
        .split(';')
        .map(|a| a.trim().to_string())
        .collect())
}
