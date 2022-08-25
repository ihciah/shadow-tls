# Shadow TLS
A proxy to expose real tls handshake to the firewall.

It works like [trojan](https://github.com/trojan-gfw/trojan) but it does not require signing certificate. The firewall will see **real** tls handshake with **valid certificate** that you choose.

## Run
Check comments in `docker-compose.yml`.

## How it Works
On client side, just do tls handshake. And for server, we have to relay data as well as parsing tls handshake to handshaking server which will provide valid certificate. We need to know when the tls handshaking is finished. Once finished, we can relay data to our real server.

## Note
This project relies on [Monoio](https://github.com/bytedance/monoio) which is a high performance rust async runtime with io_uring. However, it does not support windows yet. So this project does not support windows.

However, if this project is used widely, we will support it by conditional compiling.