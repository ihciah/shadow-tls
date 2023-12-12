use std::time::Duration;

use monoio::{
    io::{AsyncReadRentExt, AsyncWriteRentExt},
    net::TcpStream,
};
use monoio_rustls_fork_shadow_tls::TlsConnector;
use rustls_fork_shadow_tls::{OwnedTrustAnchor, RootCertStore, ServerName};
use shadow_tls::{RunningArgs, TlsAddrs, V3Mode};

#[allow(unused)]
mod utils;
use utils::{CAPTIVE_HTTP_REQUEST, CAPTIVE_HTTP_RESP};

#[monoio::test(enable_timer = true)]
async fn sni() {
    // construct tls connector
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.as_ref(),
            ta.subject_public_key_info.as_ref(),
            ta.name_constraints.as_ref().map(|n| n.as_ref()),
        )
    }));
    let tls_config = rustls_fork_shadow_tls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let tls_connector = TlsConnector::from(tls_config);

    // run server
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:32000".to_string(),
        target_addr: "bing.com:80".to_string(),
        tls_addr: TlsAddrs::try_from("captive.apple.com").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Strict,
    };
    server.build().expect("build server failed").start(1);
    monoio::time::sleep(Duration::from_secs(1)).await;

    // connect and handshake
    let mut captive_conn = tls_connector
        .connect(
            ServerName::try_from("captive.apple.com").unwrap(),
            TcpStream::connect("127.0.0.1:32000").await.unwrap(),
        )
        .await
        .expect("unable to connect captive.apple.com");
    captive_conn
        .write_all(CAPTIVE_HTTP_REQUEST)
        .await
        .0
        .unwrap();

    let (res, buf) = captive_conn
        .read_exact(vec![0; CAPTIVE_HTTP_RESP.len()])
        .await;
    assert!(res.is_ok());
    assert_eq!(&buf, CAPTIVE_HTTP_RESP);
}
