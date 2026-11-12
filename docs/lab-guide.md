#  Lab Guide: Capturing & Analyzing Traffic with Wireshark

This guide walks you through a full hands-on lab: installing Wireshark, capturing traffic on your own machine, and manually identifying each traffic type called for in the project (HTTP, DNS, TCP handshakes, IP addresses, suspicious patterns, unencrypted data).

> **Only capture traffic on a network you own or are explicitly authorized to monitor** — e.g., your home Wi-Fi, or a personal VM lab. Do not run this on a school, work, or public network without permission.

---

## 1. Install Wireshark

- Download from [wireshark.org/download.html](https://www.wireshark.org/download.html)
- During install on Windows, allow the **Npcap** driver install (required for live capture)
- On macOS/Linux, you may need to grant capture permissions to your user (`sudo usermod -aG wireshark $USER` on Linux, then log out/in)

---

## 2. Start a Capture

1. Open Wireshark
2. Select your active network interface (Wi-Fi or Ethernet) — the one showing traffic activity in the live sparkline
3. Click the blue shark-fin **Start Capture** button
4. In a browser, visit a **plain HTTP** site (not HTTPS) so you have unencrypted traffic to inspect. `http://neverssl.com` is designed exactly for this purpose. Also visit a normal HTTPS site (e.g. `https://example.com`) for comparison.
5. After ~15–30 seconds, click the red square **Stop Capture** button
6. Save the capture: `File → Save As → my_capture.pcapng`

---

## 3. Identify TCP Handshakes

Every TCP connection starts with a 3-way handshake:

```
Client  --- SYN --->        Server
Client  <-- SYN, ACK ---    Server
Client  --- ACK --->        Server
```

**In Wireshark:**
- Apply the display filter: `tcp.flags.syn == 1 && tcp.flags.ack == 0` to find the initial SYN packets
- Right-click one → **Follow → TCP Stream** to see the entire conversation
- Look at the **Flags** field in the packet detail pane (bottom-left) under the TCP layer — you'll see `[SYN]`, `[SYN, ACK]`, and `[ACK]` labeled explicitly in the packet list's Info column

**What to record:** source IP:port, destination IP:port, and whether all three steps completed.

---

## 4. Identify DNS Requests

**Filter:** `dns`

Each row shows either a `Standard query` (the request) or `Standard query response` (the answer). Expand a packet's **Domain Name System** section to see:
- The queried domain name
- The resolved IP address(es) in the `Answers` section
- The DNS server that answered (usually your router or a public resolver like `8.8.8.8` / `1.1.1.1`)

**What to record:** domain name queried, resolved IP, and which DNS server answered.

---

## 5. Identify HTTP Traffic

**Filter:** `http`

You'll see `GET`, `POST`, and `HTTP/1.1 200 OK` style entries in the Info column. Click on a request packet and expand **Hypertext Transfer Protocol** to see:
- Request method, path, and headers (`Host`, `User-Agent`, `Cookie`, etc.)
- Any form data submitted (visible in POST bodies — this is the unencrypted data exposure risk)

**Compare with HTTPS traffic** (`filter: tls` or `ssl`) — notice how you can see almost nothing about the actual content, just the handshake and encrypted `Application Data` — this is the whole point of HTTPS.

---

## 6. Identify IP Addresses & Conversations

**Menu:** `Statistics → Conversations → IPv4 tab`

This gives you a clean table of every pair of IP addresses that talked, how many packets/bytes were exchanged, and duration. Useful for quickly spotting:
- Which external servers your machine is talking to
- Any single host generating unusually high traffic volume

---

## 7. Spot Unencrypted Data Exposure

While viewing an `http` filtered POST request (e.g. a login form on an HTTP-only test site), right-click → **Follow → HTTP Stream**. If the site sends credentials in plaintext, you'll see the literal `username=...&password=...` values in the stream — a clear, visceral demonstration of why HTTPS matters.

**Never do this against a real site with your real password.** Use a test/dummy account on a site like `neverssl.com`, or use the synthetic sample pcap included in this repo (`sample_captures/sample_traffic.pcap`) which was generated offline specifically for this purpose.

---

## 8. Spot Suspicious Traffic Patterns

A few beginner-friendly things to look for:

| Pattern | Wireshark filter | What it might indicate |
|---|---|---|
| One host hitting many ports fast | `tcp.flags.syn==1 && tcp.flags.ack==0` sorted by dest port | Port scanning |
| Traffic on unexpected ports | `tcp.port == 4444` (or similar odd port) | Possible reverse shell / malware C2 |
| Repeated failed connections | look for many `[RST, ACK]` from one host | Blocked/refused connection attempts |
| Cleartext protocols in use | `ftp`, `telnet`, `http` (vs `ftps`, `ssh`, `https`) | Unencrypted, interceptable traffic |
| Unusual DNS query volume | `dns` sorted/grouped by source | Possible malware beaconing or DNS tunneling |

---

## 9. Automate the Analysis

Once you're comfortable identifying these manually, use the included Python analyzer to do it programmatically:

```bash
python scripts/analyze_pcap.py path/to/my_capture.pcapng
```

This reproduces the same checks (handshakes, DNS, HTTP, unencrypted exposure, suspicious patterns) as a repeatable script — useful for larger captures where manual review doesn't scale.

---

## 10. Write Up Your Findings

Use [`docs/report-template.md`](report-template.md) to document what you found. This is the piece you'll want to showcase in your GitHub README or portfolio — screenshots plus a clear explanation of what each traffic type looked like and why it matters.
