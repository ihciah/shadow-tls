use shadow_tls::{RunningArgs, TlsAddrs, TlsExtConfig, TlsNames, V3Mode};

mod utils;
use utils::*;

// handshake: feishu.cn(tls1.3)
// data: t.cn:80
// protocol: v2
#[test]
fn tls13_v2() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:20006".to_string(),
        target_addr: "127.0.0.1:20007".to_string(),
        tls_names: TlsNames::try_from("feishu.cn").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        v3: V3Mode::Disabled,
    };
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:20007".to_string(),
        target_addr: "t.cn:80".to_string(),
        tls_addr: TlsAddrs::try_from("feishu.cn").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        v3: V3Mode::Disabled,
    };
    test_ok(client, server, T_CN_HTTP_REQUEST, T_CN_HTTP_RESP);
}

// handshake: feishu.cn(tls1.3)
// data: t.cn:80
// protocol: v3 lossy
#[test]
fn tls13_v3_lossy() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:20008".to_string(),
        target_addr: "127.0.0.1:20009".to_string(),
        tls_names: TlsNames::try_from("feishu.cn").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        v3: V3Mode::Lossy,
    };
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:20009".to_string(),
        target_addr: "t.cn:80".to_string(),
        tls_addr: TlsAddrs::try_from("feishu.cn").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        v3: V3Mode::Lossy,
    };
    utils::test_ok(client, server, T_CN_HTTP_REQUEST, T_CN_HTTP_RESP);
}

// handshake: feishu.cn(tls1.3)
// data: t.cn:80
// protocol: v3 strict
#[test]
fn tls13_v3_strict() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:20010".to_string(),
        target_addr: "127.0.0.1:20011".to_string(),
        tls_names: TlsNames::try_from("feishu.cn").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        v3: V3Mode::Strict,
    };
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:20011".to_string(),
        target_addr: "t.cn:80".to_string(),
        tls_addr: TlsAddrs::try_from("feishu.cn").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        v3: V3Mode::Strict,
    };
    utils::test_ok(client, server, T_CN_HTTP_REQUEST, T_CN_HTTP_RESP);
}
