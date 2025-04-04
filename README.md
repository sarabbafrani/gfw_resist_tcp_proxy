# GFW Resist TCP Proxy (Fork by @sarabbafrani)

This project is a proof-of-concept TCP proxy designed to **bypass IP blocking by the Great Firewall (GFW)** by **violating the standard TCP handshake**.  
It uses crafted packets to avoid detection, allowing connections to blocked IPs in China.

> Original Project: [GFW-knocker/gfw_resist_tcp_proxy](https://github.com/GFW-knocker/gfw_resist_tcp_proxy)

---

## ✨ Features

- Bypasses GFW IP-based censorship using raw TCP packets
- Works at a low level, protocol-agnostic
- Compatible with both Linux client and server
- Uses Python and Scapy
- Fully automated setup script

---

## 🚀 One-Line Installation (Recommended)

Run this on **your VPS or local machine**, and follow the prompt:

```bash
bash <(curl -s https://raw.githubusercontent.com/sarabbafrani/gfw_resist_tcp_proxy/main/gfw_resist_tcp_proxy_setup.sh)
