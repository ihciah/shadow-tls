---
title: ShadowTLS V3 Protocol
date: 2023-02-06 11:00:00
updated: 2023-02-11 20:00:00
author: ihciah
---

# Version Evolution
In August 2022 I implemented the first version of the ShadowTLS protocol. The goal of the V1 protocol was simple: to evade man-in-the-middle traffic discrimination by simply proxying the TLS handshake. v1 assumed that the man-in-the-middle would only observe handshake traffic, not subsequent traffic, not active probes, and not traffic hijacking.

However, this assumption does not hold true. In order to defend against active probing, the V2 version of the protocol added a mechanism to verify the identity of the client by challenge-response; and added Application Data encapsulation to better disguise the traffic.

The V2 version works well so far, and I have not encountered any problem of being blocked in daily use. After implementing support for multiple SNIs, it can even work as an SNI Proxy, which doesn't look like a proxy for data smuggling at all.

But the V2 protocol still assumes that the middleman will not do traffic hijacking (refer to [issue](https://github.com/ihciah/shadow-tls/issues/30)). The cost of traffic hijacking is relatively high, and it is not widely used at present. The means of man-in-the-middle are still mainly bypass observation and injection, and active detection. However, this does not mean that traffic hijacking will not be used on a large scale in the future, and protocols designed to resist traffic hijacking must be a better solution. One of the biggest problems faced is that it is difficult for the server side to identify itself covertly.

The [restls](https://github.com/3andne/restls) proposed in this [issue](https://github.com/ihciah/shadow-tls/issues/66) provides a very innovative idea. With this idea we can solve the server-side identity problem.

In addition, I also mentioned in [this blog](https://www.ihcblog.com/a-better-tls-obfs-proxy/) some possible hijacking attacks against data encapsulation, which must be addressed by the V3 protocol.


# V3 Protocol Principle
1. Capable of defending against traffic signature detection, active detection and traffic hijacking.
2. Easier to implement correctly.
3. Be as weakly aware of the TLS protocol itself as possible, so implementers do not need to hack the TLS library, let alone implement the TLS protocol themselves.
4. Keep it simple: only act as a TCP flow proxy, no duplicate wheel building.

## About support for TLS 1.2
The V3 protocol only supports handshake servers that use TLS1.3. You can use `openssl s_client -tls1_3 -connect example.com:443` to probe a server for TLS1.3 support.

To support TLS1.2 would require more awareness of TLS protocol details and would be more complex to implement; given that TLS1.3 is already used by more vendors, we decided to support only TLS1.3.

# Handshake
This part of the protocol design is based on [restls](https://github.com/3andne/restls), but there are some differences: it is less aware of the details of TLS and easier to implement.

The client's TLS Client constructs the ClientHello, which generates a custom SessionID. The length of the SessionID must be 32, the first 28 bits are random values, and the last 4 bits are the HMAC signature data of the ClientHello frame (without the 5-byte header of the TLS frame, the 4 bytes after the SessionID are filled with 0). The HMAC instance is for one-time use only, and the instance is created directly using the password. A Read Wrapper is also needed to extract the ServerRandom from ServerHello and forward the subsequent streams. 2.
When the server receives the packet, it will authenticate the ClientHello, and if the authentication fails, it will continue the TCP relay with the handshake server. If the identification is successful, it will also forward it to the handshake server and continuously hijack the return stream from the handshake server. The server side will.
    1. log the ServerRandom in the forwarded ServerHello.
    2. do the following with the content portion of all ApplicationData frames.
        1. transform the data to XOR SHA256 (PreSharedKey + ServerRandom). 2.
        2. Add the 4 byte prefix `HMAC_ServerRandom(processed frame data)`, the HMAC instance should be filled with ServerRandom as the initial value, and this HMAC instance should be reused for subsequent ApplicationData forwarded from the handshake server. Note that the frame length needs to be + 4 at the same time. 3.
The client's ReadWrapper needs to parse the ApplicationData frame and determine the first 4 byte HMAC: 1.
    1. If `HMAC_ServerRandom(frame data)` is met, the server is proven to be reliable. These frames need to be filtered out after the handshake is complete. 2.
    2. If `HMAC_ServerRandomS(frame data)` is met, it proves that the data has finished switching. The content part needs to be forwarded to the user side.
    3. If none of them match, the traffic may have been hijacked and the handshake needs to be continued (or stopped if the handshake fails) and a random length HTTP request (muddled request) sent after a successful handshake and the connection closed properly after the response is read.

## Security Verification
1. When traffic is hijacked, Server will return data without doing XOR and Client will go straight to the muddling process.
2. ClientHello may be replayed but cannot use its correct handshake ([discussion of restls](https://github.com/3andne/restls/blob/main/Restls%3A%20%E5%AF%B9TLS%E6%8F%A1%E6%89%8B%E7%9A%84%E5%AE%8C%E7%BE%8E%E4%BC%AA%E8%A3%85.md)), so there is no way to identify whether the XOR data we return with a prefix is decodable.
2. If Client pretends the data is decrypted successfully and sends the data directly, it will not be able to pass because of the data frame checksum.

# Data Encapsulation
The V2 version of the data encapsulation protocol is in fact not resistant to traffic hijacking, e.g., the middleman may tamper with this part of the data after the handshake is completed, and we need to be able to respond to Alert; the middleman may also split one ApplicationData package into two as in the V2 protocol, which can also be used to identify the protocol if the connection is normal.

To deal with traffic hijacking, in addition to optimizing the handshake process, the data encapsulation part also needs to be redesigned. We need to be able to authenticate the data stream and resist attacks such as replay, data tampering, data slicing, and data disorder.

In addition to continuing to use ApplicationData encapsulation for the outermost layer of data, we added a 4 byte HMAC computed value to the inner layer. After we create the HMAC instance with the preshared key, we fill in `ServerRandom+"C"` or `ServerRandom+"S"` as the initial value, the former corresponds to the sent data stream of the Client, the latter corresponds to the sent data stream of the Server (the purpose is to prevent the man-in-the-middle from sending back the data we sent, or replaying (the purpose is to prevent the middleman from sending back the data we sent or replaying the data from different connections). In the forwarding process, the pure data is first filled into the HMAC instance, and then the 4 byte value is calculated and placed at the top of the pure data. The encapsulated data frame format: (5B tls frame header)(4B HMAC)(data). After encapsulation, the 4 byte data is fed into the HMAC instance (to avoid man-in-the-middle cut splicing requests).

When the data checksum fails, we need to send a TLS Alert immediately to close the connection properly. We also need to be able to close the connection correctly when it is broken.

## Security Verification
1. For man-in-the-middle data tampering, HMAC will directly verify it and will respond to Alert.
2. For man-in-the-middle disorder attack, HMAC will directly verify it and respond to Alert.
3. For cut and splice attack (merging two AppData), although HMAC is processing the data stream, we can interrupt two consecutive streams to defend against this attack because we update in an additional 4 byte value after the processing is completed.

# Implementation Guide
## Client
The client is responsible for TLS handshaking, switching and doing data encapsulation and decapsulation after the switch.

The client needs to have a built-in TLS Client and a Read Wrapper on the read side of the network stream: TLSClient <- ReadWrapper <- TCPStream; similarly, a Write Wrapper needs to be attached to the write data link: TLSClient -> WriteWrapper --> TCPStream.

Stage1: TLS handshake
Construct and sign a custom SessionID from the TLS library. 2.
ReadWrapper. 1:
    1. Extract ServerRandom from ServerHello; create `HMAC_ServerRandom`. 2.
    2. Use `HMAC_ServerRandom` for ApplicationData to determine if the HMAC of the frame content (without the 4byte HMAC) matches the first 4 bytes. If it matches, rewrite the data frame content to its XOR SHA256(PreSharedKey + ServerRandom) and remove the first 4 byte HMAC value. If it does not match, no changes are made and the connection is marked as hijacked and a muddled request is sent after a successful handshake; if the handshake fails, no processing is done.

Stage2: Data forwarding (this process does not rely on TLS library)
1. Create `HMAC_ServerRandomC` and `HMAC_ServerRandomS`. 2.
2. Parse Application Data wrapping when reading the connection and verify the first 4 bytes of data using `HMAC_ServerRandomS` and `HMAC_ServerRandom`.
    1. `HMAC_ServerRandom` passes the validation, which means this is the residual handshake data, so it is ignored.
    2. `HMAC_ServerRandomS` passes the validation, it means this is our own data encapsulation, after that `HMAC_ServerRandom` branch is disabled and the data is forwarded to the user (without HMAC)
    3. if none of them pass, the data will be handled as Alert bad_record_mac. 4.
    Note: Here the Server is allowed to send residual TLS frames to the Client after the Client has finished switching, and the Client is responsible for filtering them out. This is because Server does not strongly sense the end of TLS handshake, it only senses the data sent by Client after the switchover. 3.
3. add Application Data and HMAC when writing connection, HMAC is calculated by `HMAC_ServerRandomC`.

## Server-side
The server is responsible for forwarding the TLS handshake, determining the timing of the switch, and encapsulating and decapsulating the data after the switch, without relying on the TLS library.

Stage1: Forwarding the TLS handshake
1. Read ClientHello: extract and identify the SessionID in ClientHello, if it does not pass, mark it as active detection traffic and start TCP forwarding directly (if it implements multiple SNIs, it also needs to resolve the SNIs and do the corresponding splitting and forwarding); if it passes, it also forwards the data frame and continues to the second step.
2. Read ServerHello from the other side: extract ServerRandom.
Start two-way forwarding (with Handshake Server).
    1. Create `HMAC_ServerRandomC` and `HMAC_ServerRandom`.
    2. ShadowTLS Client -> Handshake Server: Forward directly until a frame matching the first 4 bytes of ApplicationData matches the `HMAC_ServerRandomC` signature is encountered, then stop forwarding in both directions (but ensure the integrity of the frames remaining in transit).
    3. Handshake Server -> ShadowTLS Client: modify the Application Data frame by doing XOR SHA256 (PreSharedKey + ServerRandom) on the data and adding 4 byte HMAC in the header (calculated by `HMAC_ ServerRandom`).

Stage2: Data forwarding (with Data Server)
1. Create `HMAC_ServerRandomS`.
2. ShadowTLS Client -> Data Server: Parse Application Data encapsulation and verify the first 4 bytes of data with `HMAC_ServerRandomC`. If it fails, it will be treated as Alert bad_record_mac. After validation is complete, the 4 bytes of data are also entered into the `HMAC_ServerRandomC` instance.
3. Data Server -> ShadowTLS Client: Add Application Data with HMAC, which is calculated by `HMAC_ServerRandomS`. The 4 bytes of data is then also entered into the `HMAC_ServerRandomS` instance.