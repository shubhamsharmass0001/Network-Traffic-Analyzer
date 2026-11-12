# Wireshark Display Filter Cheat Sheet

A quick reference of filters used throughout this project.

## Protocol filters
| Filter | Shows |
|---|---|
| `http` | HTTP requests & responses |
| `dns` | DNS queries & responses |
| `tcp` | All TCP traffic |
| `udp` | All UDP traffic |
| `tls` or `ssl` | TLS/SSL (HTTPS) handshake & encrypted data |
| `arp` | ARP requests/replies |
| `icmp` | Ping / ICMP traffic |
| `ftp` | FTP control traffic (cleartext!) |
| `telnet` | Telnet traffic (cleartext!) |

## TCP handshake & flags
| Filter | Shows |
|---|---|
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Initial SYN packets (connection attempts) |
| `tcp.flags.syn == 1 && tcp.flags.ack == 1` | SYN/ACK packets (server accepting) |
| `tcp.flags.reset == 1` | RST packets (refused/reset connections) |
| `tcp.flags.fin == 1` | FIN packets (graceful connection close) |

## IP / host filtering
| Filter | Shows |
|---|---|
| `ip.addr == 192.168.1.50` | All traffic to/from a specific IP |
| `ip.src == 192.168.1.50` | Traffic originating from an IP |
| `ip.dst == 8.8.8.8` | Traffic destined for an IP |
| `ip.addr == 192.168.1.0/24` | Traffic within a subnet |

## HTTP specifics
| Filter | Shows |
|---|---|
| `http.request.method == "POST"` | Only POST requests (form submissions, logins) |
| `http.request.method == "GET"` | Only GET requests |
| `http contains "password"` | Packets with "password" in plaintext (crude but effective) |
| `http.response.code == 200` | Successful HTTP responses |
| `http.response.code >= 400` | Client/server error responses |

## Port-based
| Filter | Shows |
|---|---|
| `tcp.port == 80` | HTTP traffic (cleartext) |
| `tcp.port == 443` | HTTPS traffic (encrypted) |
| `tcp.port == 21` | FTP control (cleartext) |
| `tcp.port == 22` | SSH (encrypted) |
| `tcp.port == 23` | Telnet (cleartext) |
| `udp.port == 53` | DNS |

## Useful combos
| Filter | Shows |
|---|---|
| `http or dns` | HTTP and DNS together |
| `tcp.flags.syn==1 and ip.dst==10.0.0.5` | All SYNs targeting a specific host (scan detection) |
| `!(arp or icmp)` | Hide noisy ARP/ICMP to focus on "real" traffic |

## Useful menus (not filters)
- `Statistics → Conversations` — who talked to whom, and how much
- `Statistics → Protocol Hierarchy` — breakdown of traffic by protocol
- `Statistics → Endpoints` — every unique IP seen in the capture
- Right-click a packet → `Follow → TCP Stream` / `HTTP Stream` — reconstruct the full conversation
