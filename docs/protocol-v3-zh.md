---
title: ShadowTLS V3 协议设计
date: 2023-02-06 11:00:00
updated: 2023-02-06 11:00:00
author: ihciah
---

# 版本演进
在 2022 年 8 月的时候我实现了第一版 ShadowTLS 协议。当时 V1 协议的目标非常简单，仅仅通过代理 TLS 握手来逃避中间人对流量的判别。V1 协议假定中间人只会观察握手流量，不会观察后续流量、不会做主动探测，也不会做流量劫持。

但这个假设并不成立。为了防御主动探测，在 V2 版本的协议中添加了通过 challenge-response 方式来验证客户端身份的机制；并新增了 Application Data 封装来更好地伪装流量。

V2 版本目前工作良好，在日常使用中我没有遇到被封锁等问题。在实现了对多 SNI 的支持后，它甚至可以作为一个 SNI Proxy 工作，看起来完全不像是一个偷渡数据用的代理。

但是 V2 协议仍假设中间人不会对流量做劫持（参考 [issue](https://github.com/ihciah/shadow-tls/issues/30)）。流量劫持成本比较高，目前没有被广泛应用，目前中间人的手段仍以旁路观测和注入以及主动探测为主。但这并不意味这未来流量劫持不会被大规模使用，协议设计上能够抵御流量劫持一定是更好的方案。面临的最大的一个问题是，服务端很难隐蔽地表明身份。

这个 [issue](https://github.com/ihciah/shadow-tls/issues/66) 提出的 [restls](https://github.com/3andne/restls) 提供了一个极具创新性的思路。借鉴这个思路我们可以解决服务端身份鉴定问题。

除此之外，我在[这篇博客](https://www.ihcblog.com/a-better-tls-obfs-proxy/)里也提到了一些针对数据封装的可能的劫持攻击，这也是 V3 协议必须解决的问题。

# V3 协议目标
1. 能够防御流量特征检测、主动探测和流量劫持。
2. 更易于正确实现。
3. 尽可能地弱感知 TLS 协议本身，实现者无需 Hack TLS 库，更不需要自行实现 TLS 协议。
4. 保持简单：仅作为 TCP 流代理，不重复造轮子。

## 关于对 TLS 1.2 的支持
V3 协议仅支持使用 TLS1.3 的握手服务器。你可以使用 `openssl s_client -tls1_3 -connect example.com:443` 来探测一个服务器是否支持 TLS1.3。

如果要支持 TLS1.2，需要感知更多 TLS 协议细节，实现起来会更加复杂；鉴于 TLS1.3 已经有较多厂商使用，我们决定仅支持 TLS1.3。

# 握手流程
这部分协议设计借鉴 [restls](https://github.com/3andne/restls) 但存在一定差别：弱化了对 TLS 细节的感知，更易于实现。

1. 客户端的 TLS Client 构造 ClientHello，ClientHello 需要生成自定义的 SessionID。SessionID 长度需为 32，前 28 位是随机值，后 4 位是 ClientHello 帧（不含 TLS 帧的 5 字节头，SessionID 后 4 byte 填充 0）的 HMAC 签名数据。HMAC 实例仅为一次性使用，直接使用密码创建实例。同时需要一个 Read Wrapper 负责提取 ServerHello 中的 ServerRandom 并转发后续流。
2. 服务端收到包后，会对 ClientHello 做鉴定，如果鉴定失败则直接持续性与握手服务器进行 TCP 中继。如果鉴定成功，也会将其转发至握手服务器，并持续劫持握手服务器的返回数据流。服务端会：
    1. 记录转发的 ServerHello 中的 ServerRandom。
    2. 对所有 ApplicationData 帧的内容部分做处理：
        1. 对数据做变换，将其 XOR SHA256(PreSharedKey + ServerRandom)。
        2. 添加 4 byte 前缀 `HMAC_ServerRandom(处理后的帧数据)`，HMAC 实例需事先灌入 ServerRandom 作为初始值，对此后从握手服务器转发的 ApplicationData 需要复用这个 HMAC 实例。注意帧长度需要同时 + 4。
3. 客户端的 ReadWrapper 需要解析 ApplicationData 帧，判定前 4 byte HMAC：
    1. 符合 `HMAC_ServerRandom(帧数据)`，则证明服务端是可靠的。在握手完成后这类帧需要过滤掉。
    2. 符合 `HMAC_ServerRandomS(帧数据)`，则证明数据已经完成切换。需要将内容部分转发至用户侧。
    3. 都不符合，此时可能流量已被劫持，需要继续握手（握手失败则作罢），并在握手成功后发送一个长度随机的 HTTP 请求（糊弄性请求），在读取完响应后正确关闭连接。

## 安全性验证
1. 流量劫持时，Server 会返回没有做 XOR 的数据，Client 会直接进入糊弄流程。
2. ClientHello 可能会被重放，但无法使用其正确握手([restls 的讨论](https://github.com/3andne/restls/blob/main/Restls%3A%20%E5%AF%B9TLS%E6%8F%A1%E6%89%8B%E7%9A%84%E5%AE%8C%E7%BE%8E%E4%BC%AA%E8%A3%85.md))，所以无法鉴别我们返回的带前缀的 XOR 数据是否可解密。
2. 若 Client 假装数据解密成功，直接发送数据，由于存在数据帧校验，其也无法通过。

# 数据封装
V2 版本的数据封装协议事实上也无法抵御流量劫持，如中间人可能会在握手完成后对这部分数据做篡改，我们需要能够响应 Alert；中间人也可能会按照 V2 协议的样子将一个 ApplicationData 封装拆成两个，如果连接正常，则也可以用于识别协议。

要应对流量劫持，除了要优化握手流程，数据封装部分也要重新设计。我们需要能够对数据流做验证，并且抵御重放、数据篡改、数据切分、数据乱序等攻击。

数据除了最外层继续使用 ApplicationData 封装外，内层添加了 4 byte 的 HMAC 计算值。我们在使用 preshared key 创建 HMAC 实例后，会灌入 `ServerRandom+"C"` 或 `ServerRandom+"S"` 作为初始值，前者对应 Client 的发送数据流，后者对应 Server 的发送数据流（目的是防止中间人将我们发送的数据发回来，或者将不同连接的数据重放）。在转发过程中，首先将纯数据灌入 HMAC 实例，之后计算 4 byte 值后放于纯数据最前面。封装出的数据帧格式：(5B tls frame header)(4B HMAC)(data)。封装结束后将 4 byte 数据输入 HMAC 实例（避免中间人剪切拼接请求）。

当数据校验失败时，我们需要立刻发送 TLS Alert 正确关闭连接。在连接断开时也需要能够正确关闭。

## 安全性验证
1. 对于中间人的数据篡改，HMAC 会直接验证出来，会响应 Alert。
2. 对于中间人乱序攻击，HMAC 会直接验证出来，会响应 Alert。
3. 对于剪切拼接攻击（合并两个 AppData），虽然 HMAC 处理的是数据流，但是由于我们在处理完成后又额外 update 进去一个 4 byte 的值，所以可以打断两个连续的流，防御这种攻击。

# 实现指南
## 客户端
客户端负责 TLS 握手、切换并在切换后做数据封装和解封装。

客户端需要内置一个 TLS Client，并在其对网络流读时加一层 Read Wrapper：TLSClient <- ReadWrapper <- TCPStream；同样，在写数据链路上也需要附加一个 Write Wrapper：TLSClient -> WriteWrapper -> TCPStream。

Stage1: TLS 握手
1. 通过 TLS 库构造自定义 SessionID 并签名。
2. ReadWrapper:
    1. 提取 ServerHello 中的 ServerRandom；创建 `HMAC_ServerRandom`。
    2. 对 ApplicationData 使用 `HMAC_ServerRandom` 判定帧内容（不含 4byte HMAC）的 HMAC 与前 4 byte 是否匹配。若匹配则重写数据帧内容为其 XOR SHA256(PreSharedKey + ServerRandom)，并去掉前 4 byte HMAC 值。若不匹配则不做修改，并标记该连接被劫持，握手成功后发送糊弄性请求；握手失败则不做处理。

Stage2: 数据转发（该过程不依赖 TLS 库）
1. 创建 `HMAC_ServerRandomC` 和 `HMAC_ServerRandomS`。
2. 读连接时 Parse Application Data 封装，并利用 `HMAC_ServerRandomS` 和 `HMAC_ServerRandom` 验证数据前 4 byte。
    1. `HMAC_ServerRandom` 通过验证则表示这个是握手残留数据，直接忽略。
    2. `HMAC_ServerRandomS` 通过验证则表示这个是我们自己的数据封装，此后禁用 `HMAC_ServerRandom` 分支判定，并将数据转发至用户（不含 HMAC）
    3. 均未通过，则按照 Alert bad_record_mac 处理。
    4. 说明：这里允许 Server 在 Client 完成切换后向 Client 发送残留的 TLS 帧，客户端需要负责过滤掉。因为 Server 并不强感知 TLS 握手结束，其仅感知 Client 发送切换后的数据。
3. 写连接时添加 Application Data 与 HMAC，HMAC 通过 `HMAC_ServerRandomC` 计算得到。

## 服务端
服务端负责转发 TLS 握手、判定切换时机并在切换后做数据封装和解封装，它不依赖 TLS 库。

Stage1: 转发 TLS 握手
1. 读 ClientHello: 提取并鉴定 ClientHello 中的 SessionID，若未通过则标记为主动探测流量，后续直接启动 TCP 转发（实现多 SNI 的话还需要解析 SNI 并做对应分流转发）；若通过也会转发该数据帧，并继续第二步。
2. 从另一侧读 ServerHello: 提取 ServerRandom。
3. 启动双向转发(with Handshake Server):
    1. 创建 `HMAC_ServerRandomC` 和 `HMAC_ServerRandom`。
    2. ShadowTLS Client -> Handshake Server: 直接转发，直到遇到符合 ApplicationData 前 4 byte 符合 `HMAC_ServerRandomC` 签名结果的数据帧，此时停止双向转发（但需要保证残留正在发送中的帧的完整性）。
    3. Handshake Server -> ShadowTLS Client: 对 Application Data 帧做修改，对数据做 XOR SHA256(PreSharedKey + ServerRandom) 之后在头部添加 4 byte HMAC（由 `HMAC_ServerRandom` 计算）。

Stage2: 数据转发(with Data Server)
1. 创建 `HMAC_ServerRandomS`。
2. ShadowTLS Client -> Data Server: Parse Application Data 封装，并利用 `HMAC_ServerRandomC` 验证数据前 4 byte。若未通过，则按照 Alert bad_record_mac 处理。验证完成后，将该 4 字节数据也输入到 `HMAC_ServerRandomC` 实例中。
3. Data Server -> ShadowTLS Client: 添加 Application Data 与 HMAC，HMAC 通过 `HMAC_ServerRandomS` 计算得到。之后将该 4 字节数据也输入到 `HMAC_ServerRandomS` 实例中。
