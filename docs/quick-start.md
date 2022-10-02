---
title: 快速开始
date: 2022-10-02 11:00:00
author: ihciah
---

TODO：待完善

## 参考的 docker-compose 文件
命名为 `docker-compose.yml` 后可以在该文件夹下 `docker-compose up -d` 启动。

Server:
```yaml
version: '2.4'
services:
  shadowsocks:
    image: shadowsocks/shadowsocks-libev
    container_name: shadowsocks-raw
    restart: always
    network_mode: "host"
    environment:
      - SERVER_PORT=24000
      - SERVER_ADDR=127.0.0.1
      - METHOD=chacha20-ietf-poly1305
      - PASSWORD=EXAMPLE_PASSWORD_CHANGE_IT
  shadow-tls:
    image: ghcr.io/ihciah/shadow-tls:latest
    restart: always
    network_mode: "host"
    environment:
      - MODE=server
      - LISTEN=0.0.0.0:8443
      - SERVER=127.0.0.1:24000
      - TLS=cloud.tencent.com:443
      - PASSWORD=CHANGE_IT_123321
```

Client:
```yaml
version: '2.4'
services:
  shadow-tls:
    image: ghcr.io/ihciah/shadow-tls:latest
    restart: always
    network_mode: "host"
    environment:
      - MODE=client
      - LISTEN=0.0.0.0:24000
      - SERVER=your_vps_ip:8443
      - TLS=cloud.tencent.com
      - PASSWORD=CHANGE_IT_123321
```
