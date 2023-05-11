use shadow_tls::{RunningArgs, TlsAddrs, TlsExtConfig, TlsNames, V3Mode};

#[allow(unused)]
mod utils;
use utils::*;

// handshake: bing.com(tls1.2 only)
// data: captive.apple.com:80
// protocol: v2
#[test]
fn tls12_v2() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:30000".to_string(),
        target_addr: "127.0.0.1:30001".to_string(),
        tls_names: TlsNames::try_from("bing.com").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Disabled,
    };
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:30001".to_string(),
        target_addr: "captive.apple.com:80".to_string(),
        tls_addr: TlsAddrs::try_from("bing.com").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Disabled,
    };
    test_ok(client, server, CAPTIVE_HTTP_REQUEST, CAPTIVE_HTTP_RESP);
}

// handshake: bing.com(tls1.2 only)
// data: captive.apple.com:80
// protocol: v3 lossy
#[test]
fn tls12_v3_lossy() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:30002".to_string(),
        target_addr: "127.0.0.1:30003".to_string(),
        tls_names: TlsNames::try_from("bing.com").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Lossy,
    };
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:30003".to_string(),
        target_addr: "captive.apple.com:80".to_string(),
        tls_addr: TlsAddrs::try_from("bing.com").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Lossy,
    };
    utils::test_ok(client, server, CAPTIVE_HTTP_REQUEST, CAPTIVE_HTTP_RESP);
}

// handshake: bing.com(tls1.2 only)
// data: captive.apple.com:80
// protocol: v3 strict
// v3 strict cannot work with tls1.2, so it must fail
#[test]
#[should_panic]
fn tls12_v3_strict() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:30004".to_string(),
        target_addr: "127.0.0.1:30005".to_string(),
        tls_names: TlsNames::try_from("bing.com").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Strict,
    };
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:30005".to_string(),
        target_addr: "captive.apple.com:80".to_string(),
        tls_addr: TlsAddrs::try_from("bing.com").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Strict,
    };
    utils::test_ok(client, server, CAPTIVE_HTTP_REQUEST, CAPTIVE_HTTP_RESP);
}

// handshake: bing.com(tls1.2 only)
// data: bing.com:443
// protocol: v2
// Note: v2 can not defend against hijack attack.
// Here hijack means directly connect to the handshake server.
// The interceptor will see TLS Alert.
// But it will not cause data error since the connection will be closed.
#[test]
fn tls12_v2_hijack() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:30006".to_string(),
        target_addr: "bing.com:443".to_string(),
        tls_names: TlsNames::try_from("bing.com").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Disabled,
    };
    test_hijack(client);
}

// handshake: bing.com(tls1.2 only)
// data: captive.apple.com:80
// protocol: v3 lossy
// (v3 strict can not work with tls1.2)
// Note: tls1.2 with v3 lossy can not defend against hijack attack.
// Here hijack means directly connect to the handshake server.
// The interceptor will see TLS Alert.
// But it will not cause data error since the connection will be closed.
#[test]
fn tls12_v3_lossy_hijack() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:30007".to_string(),
        target_addr: "bing.com:443".to_string(),
        tls_names: TlsNames::try_from("bing.com").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Lossy,
    };
    test_hijack(client);
}
