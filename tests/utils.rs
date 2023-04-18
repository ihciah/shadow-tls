use std::{
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    time::Duration,
};

use shadow_tls::RunningArgs;

pub const BING_HTTP_REQUEST: &[u8; 47] = b"GET / HTTP/1.1\r\nHost: bing.com\r\nAccept: */*\r\n\r\n";
pub const BING_HTTP_RESP: &[u8; 12] = b"HTTP/1.1 301";

pub const CAPTIVE_HTTP_REQUEST: &[u8; 56] =
    b"GET / HTTP/1.1\r\nHost: captive.apple.com\r\nAccept: */*\r\n\r\n";
pub const CAPTIVE_HTTP_RESP: &[u8; 15] = b"HTTP/1.1 200 OK";

pub fn test_ok(
    client: RunningArgs,
    server: RunningArgs,
    http_request: &[u8],
    http_response: &[u8],
) {
    let client_listen = match &client {
        RunningArgs::Client { listen_addr, .. } => listen_addr.clone(),
        RunningArgs::Server { .. } => panic!("not valid client args"),
    };
    client.build().expect("build client failed").start(1);
    server.build().expect("build server failed").start(1);

    // sleep 1s to make sure client and server have started
    std::thread::sleep(Duration::from_secs(3));
    let mut conn = TcpStream::connect(client_listen).unwrap();
    conn.write_all(http_request)
        .expect("unable to send http request");
    conn.shutdown(Shutdown::Write).unwrap();

    let mut buf = vec![0; http_response.len()];
    conn.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, http_response);
}

pub fn test_hijack(client: RunningArgs) {
    let client_listen = match &client {
        RunningArgs::Client { listen_addr, .. } => listen_addr.clone(),
        RunningArgs::Server { .. } => panic!("not valid client args"),
    };
    client.build().expect("build client failed").start(1);

    // sleep 1s to make sure client and server have started
    std::thread::sleep(Duration::from_secs(3));
    let mut conn = TcpStream::connect(client_listen).unwrap();
    conn.write_all(b"dummy").unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut dummy_buf = [0; 1];
    assert!(!matches!(conn.read(&mut dummy_buf), Ok(1)));
}
