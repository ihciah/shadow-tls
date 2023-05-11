use shadow_tls::{RunningArgs, TlsAddrs, TlsExtConfig, TlsNames, V3Mode};

#[allow(unused)]
mod utils;
use utils::*;

// handshake: captive.apple.com(tls1.3)
// data: bing.com:80
// protocol: v2
#[test]
fn tls13_v2() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:31000".to_string(),
        target_addr: "127.0.0.1:31001".to_string(),
        tls_names: TlsNames::try_from("captive.apple.com").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Disabled,
    };
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:31001".to_string(),
        target_addr: "bing.com:80".to_string(),
        tls_addr: TlsAddrs::try_from("captive.apple.com").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Disabled,
    };
    test_ok(client, server, BING_HTTP_REQUEST, BING_HTTP_RESP);
}

// handshake: captive.apple.com(tls1.3)
// data: bing.com:80
// protocol: v3 lossy
#[test]
fn tls13_v3_lossy() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:31002".to_string(),
        target_addr: "127.0.0.1:31003".to_string(),
        tls_names: TlsNames::try_from("captive.apple.com").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Lossy,
    };
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:31003".to_string(),
        target_addr: "bing.com:80".to_string(),
        tls_addr: TlsAddrs::try_from("captive.apple.com").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Lossy,
    };
    utils::test_ok(client, server, BING_HTTP_REQUEST, BING_HTTP_RESP);
}

// handshake: captive.apple.com(tls1.3)
// data: bing.com:80
// protocol: v3 strict
#[test]
fn tls13_v3_strict() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:31004".to_string(),
        target_addr: "127.0.0.1:31005".to_string(),
        tls_names: TlsNames::try_from("captive.apple.com").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Strict,
    };
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:31005".to_string(),
        target_addr: "bing.com:80".to_string(),
        tls_addr: TlsAddrs::try_from("captive.apple.com").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Strict,
    };
    utils::test_ok(client, server, BING_HTTP_REQUEST, BING_HTTP_RESP);
}

// handshake: captive.apple.com(tls1.3)
// protocol: v3 lossy
// tls1.3 with v3 protocol defends against hijack attack.
#[test]
fn tls13_v3_lossy_hijack() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:31007".to_string(),
        target_addr: "captive.apple.com:443".to_string(),
        tls_names: TlsNames::try_from("captive.apple.com").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Lossy,
    };
    test_hijack(client);
}

// handshake: captive.apple.com(tls1.3)
// protocol: v3 strict
// tls1.3 with v3 protocol defends against hijack attack.
#[test]
fn tls13_v3_strict_hijack() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:31008".to_string(),
        target_addr: "captive.apple.com:443".to_string(),
        tls_names: TlsNames::try_from("captive.apple.com").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Strict,
    };
    test_hijack(client);
}
