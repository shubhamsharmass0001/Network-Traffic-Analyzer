#  Network Traffic Analysis Report

**Analyst:** [Your Name]
**Date:** [Date]
**Capture file:** [filename.pcapng]
**Capture environment:** [e.g. home network, isolated VM lab]
**Duration / packet count:** [e.g. 45 seconds, 1,204 packets]

---

## 1. Summary

_A 2–3 sentence overview of what this capture contains and the headline findings._

---

## 2. IP Addresses & Conversations

| Host A | Host B | Packets | Notes |
|---|---|---|---|
| | | | |

---

## 3. TCP Handshakes Observed

| Client | Server | Complete? | Notes |
|---|---|---|---|
| | | | |

_Screenshot:_
`![TCP handshake](../screenshots/handshake.png)`

---

## 4. DNS Activity

| Source | Domain Queried | Resolved IP |
|---|---|---|
| | | |

_Screenshot:_
`![DNS query](../screenshots/dns.png)`

---

## 5. HTTP Traffic

| Method | Host | Path | Notes |
|---|---|---|---|
| | | | |

_Screenshot:_
`![HTTP request](../screenshots/http.png)`

---

## 6. Unencrypted Data Exposure

_What plaintext data (if any) was visible? Credentials, session tokens, personal info? Compare against an HTTPS example to show the contrast._

---

## 7. Suspicious Patterns

_Anything unexpected — unusual ports, high-volume single-host traffic, repeated connection failures, cleartext protocols in use?_

---

## 8. Recommendations

_What would you recommend to secure this traffic? (e.g., "migrate the login form to HTTPS", "disable Telnet in favor of SSH", etc.)_

---

## 9. Tools Used

- Wireshark [version]
- `scripts/analyze_pcap.py` from this repo (attach JSON output if generated)
