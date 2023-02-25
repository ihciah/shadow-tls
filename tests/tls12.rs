use shadow_tls::{RunningArgs, TlsAddrs, TlsExtConfig, TlsNames, V3Mode};

mod utils;
use utils::*;

// handshake: qq.com(tls1.2 only)
// data: t.cn:80
// protocol: v2
#[test]
fn tls12_v2() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:20000".to_string(),
        target_addr: "127.0.0.1:20001".to_string(),
        tls_names: TlsNames::try_from("t.cn").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        v3: V3Mode::Disabled,
    };
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:20001".to_string(),
        target_addr: "t.cn:80".to_string(),
        tls_addr: TlsAddrs::try_from("t.cn").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        v3: V3Mode::Disabled,
    };
    test_ok(client, server, T_CN_HTTP_REQUEST, T_CN_HTTP_RESP);
}

// handshake: qq.com(tls1.2 only)
// data: t.cn:80
// protocol: v3 lossy
#[test]
fn tls12_v3_lossy() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:20002".to_string(),
        target_addr: "127.0.0.1:20003".to_string(),
        tls_names: TlsNames::try_from("t.cn").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        v3: V3Mode::Lossy,
    };
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:20003".to_string(),
        target_addr: "t.cn:80".to_string(),
        tls_addr: TlsAddrs::try_from("t.cn").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        v3: V3Mode::Lossy,
    };
    utils::test_ok(client, server, T_CN_HTTP_REQUEST, T_CN_HTTP_RESP);
}

// handshake: qq.com(tls1.2 only)
// data: t.cn:80
// protocol: v3 strict
// v3 strict cannot work with tls1.2, so it must fail
#[test]
#[should_panic]
fn tls12_v3_strict() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:20004".to_string(),
        target_addr: "127.0.0.1:20005".to_string(),
        tls_names: TlsNames::try_from("t.cn").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        v3: V3Mode::Strict,
    };
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:20005".to_string(),
        target_addr: "t.cn:80".to_string(),
        tls_addr: TlsAddrs::try_from("t.cn").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        v3: V3Mode::Strict,
    };
    utils::test_ok(client, server, T_CN_HTTP_REQUEST, T_CN_HTTP_RESP);
}
