# 🛡️ DNS Sinkhole: On-Device Tracker & Ad Neutralizer

An ultra-efficient, 100% local, zero-cloud DNS sinkhole for Android powered by native `VpnService`. Intercepts outgoing port 53 DNS queries directly on your device, matches them against a pre-loaded real-time tracker and telemetry blocklist, and sinkholes invasive domains with `0.0.0.0` answers before they ever leave your phone.

---

## ⚡ Key Highlights

- **0% Remote Proxy / 100% On-Device:** Runs an in-memory loopback TUN interface on the device itself. No remote VPN server, no middleman, and zero bandwidth overhead.
- **Microsecond DNS Response:** Intercepts UDP port 53 packets, evaluates domain suffix rules, and injects synthetic `0.0.0.0` DNS responses with TTL 60.
- **Fast-Path Resolver:** Allowed requests are piped directly to Cloudflare (`1.1.1.1`) or Google (`8.8.8.8`) via protected datagram sockets with zero packet modification.
- **Live Traffic Stream:** Live feed of all resolved domains with color-coded classification badges (`BLOCKED` vs `ALLOWED`).
- **Real-Time Analytics:** Live query counter, blocked telemetry counter, and dynamic block rate percentage.

---

## 🛠️ Architecture

```
[ Android Apps ]
       |
  (Port 53 UDP)
       v
[ Loopback TUN Interface (10.0.0.2) ]
       |
[ DnsPacketParser ] ---> [ BlocklistManager ]
                                 |
              +------------------+------------------+
              |                                     |
         [ MATCHED ]                           [ UNMATCHED ]
              |                                     |
     Synthesize 0.0.0.0                   Protected DatagramSocket
     Fast Local Response                  Forward to 1.1.1.1 (Cloudflare)
              |                                     |
              +------------------+------------------+
                                 |
                     [ Write to TUN Interface ]
```

---

## 📦 Tech Stack

- **Platform:** Android Native (Kotlin 1.9.23, Android SDK 34)
- **Networking:** `android.net.VpnService`, raw byte packet manipulation, UDP sockets
- **UI:** Material 3, ViewBinding, RecyclerView with real-time stream updates

---

## 📄 License

MIT License. Designed with privacy-first engineering.
