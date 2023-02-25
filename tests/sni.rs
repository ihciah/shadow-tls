use std::time::Duration;

use monoio::{
    io::{AsyncReadRentExt, AsyncWriteRentExt},
    net::TcpStream,
};
use monoio_rustls_fork_shadow_tls::TlsConnector;
use rustls_fork_shadow_tls::{OwnedTrustAnchor, RootCertStore, ServerName};
use shadow_tls::{RunningArgs, TlsAddrs, V3Mode};

const FEISHU_HTTP_REQUEST: &[u8; 48] = b"GET / HTTP/1.1\r\nHost: feishu.cn\r\nAccept: */*\r\n\r\n";
const FEISHU_CN_HTTP_RESP: &[u8; 30] = b"HTTP/1.1 301 Moved Permanently";

#[monoio::test(enable_timer = true)]
async fn sni() {
    // construct tls connector
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
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
        target_addr: "t.cn:80".to_string(),
        tls_addr: TlsAddrs::try_from("feishu.cn").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        v3: V3Mode::Strict,
    };
    server.build().expect("build server failed").start(1);
    monoio::time::sleep(Duration::from_secs(1)).await;

    // connect and handshake
    let mut feishu_conn = tls_connector
        .connect(
            ServerName::try_from("feishu.cn").unwrap(),
            TcpStream::connect("127.0.0.1:32000").await.unwrap(),
        )
        .await
        .expect("unable to connect feishu.cn");
    feishu_conn
        .write_all(FEISHU_HTTP_REQUEST.to_vec())
        .await
        .0
        .unwrap();
    let (res, buf) = feishu_conn
        .read_exact(vec![0; FEISHU_CN_HTTP_RESP.len()])
        .await;
    assert!(res.is_ok());
    assert_eq!(&buf, FEISHU_CN_HTTP_RESP);

    let conn = TcpStream::connect("127.0.0.1:32000").await.unwrap();
    assert!(tls_connector
        .connect(ServerName::try_from("t.cn").unwrap(), conn)
        .await
        .is_err());
}
