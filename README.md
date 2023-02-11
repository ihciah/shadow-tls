# Shadow TLS
[![Build Docker Image](https://github.com/ihciah/shadow-tls/actions/workflows/build-docker-image.yml/badge.svg)](https://github.com/ihciah/shadow-tls/pkgs/container/shadow-tls) [![Build Releas](https://github.com/ihciah/shadow-tls/actions/workflows/build-release.yml/badge.svg)](https://github.com/ihciah/shadow-tls/releases) [![Crates.io](https://img.shields.io/crates/v/shadow-tls.svg)](https://crates.io/crates/shadow-tls) [![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fihciah%2Fshadow-tls.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fihciah%2Fshadow-tls?ref=badge_shield)

一个**可以使用别人的受信证书**的 TLS 伪装代理。

它和 [trojan](https://github.com/trojan-gfw/trojan) 的表现类似，但它在做真实 TLS 握手的同时，可以直接使用别人的受信证书（如某些大公司或机构的域名），而不需要自己签发证书。当直接使用浏览器打开时，可以正常显示对应可信域名的网页内容。

---

A proxy to expose real tls handshake to the firewall.

It works like [trojan](https://github.com/trojan-gfw/trojan) but it does not require signing certificate. The firewall will see **real** tls handshake with **valid certificate** that you choose.

## How to Use It
这个服务需要双边部署，并且它一般需要搭配一个加密代理（因为本项目不包含数据加密和代理请求封装功能，这不是我们的目标）。

通常，你可以在同机部署 shadowsocks-server 和 shadowtls-server；之后在防火墙的另一端部署 shadowsocks-client 和 shadowtls-client。

有两种方式部署这个服务。
1. 使用 Docker + Docker Compose

    修改 `docker-compose.yml` 后直接 `docker-compose up -d`。
2. 使用预编译的二进制

    从 [Release 页面](https://github.com/ihciah/shadow-tls/releases)下载对应平台的二进制文件, 然后运行即可。运行指南可以 `./shadow-tls client --help` 或 `./shadow-tls server --help` 看到。

更详细的使用指南请参考 [Wiki](https://github.com/ihciah/shadow-tls/wiki/How-to-Run)。

---

Normally you need to deploy this service on both sides of the firewall. And it is usually used with an encryption proxy (because this project does not include encryption and proxy request encapsulation, which is not our goal).

1. Run with Docker + Docker Compose
 Modfy `docker-compose.yml` and run `docker-compose up -d`.

2. Use prebuilt binary
    Download the binary from [Release page](https://github.com/ihciah/shadow-tls/releases) and run it.

For more detailed usage guide, please refer to [Wiki](https://github.com/ihciah/shadow-tls/wiki/How-to-Run).

## How it Works
On client side, just do tls handshake. And for server, we have to relay data as well as parsing tls handshake to handshaking server which will provide valid certificate. We need to know when the tls handshaking is finished. Once finished, we can relay data to our real server.

Full design doc is here: [v2](./docs/protocol-en.md) | [v3](./docs/protocol-v3-en.md).

完整的协议设计: [v2](./docs/protocol-zh.md) | [v3](./docs/protocol-v3-zh.md).

## Note
This project relies on [Monoio](https://github.com/bytedance/monoio) which is a high performance rust async runtime with io_uring. However, it does not support windows yet. So this project does not support windows.

However, if this project is used widely, we will support it by conditional compiling.

Also, you may need to [modify some system limitations](https://github.com/bytedance/monoio/blob/master/docs/en/memlock.md) to make it work. If it does not work, you can add environ `MONOIO_FORCE_LEGACY_DRIVER=1` to use epoll instead of io_uring.

你可能需要修改某些系统设置来让它工作，[参考这里](https://github.com/bytedance/monoio/blob/master/docs/en/memlock.md)。如果它不起作用，您可以添加环境变量 `MONOIO_FORCE_LEGACY_DRIVER=1` 以使用 epoll 而不是 io_uring。

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fihciah%2Fshadow-tls.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fihciah%2Fshadow-tls?ref=badge_large)