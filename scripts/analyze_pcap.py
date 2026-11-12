#!/usr/bin/env python3
"""
analyze_pcap.py
----------------
Parses a .pcap/.pcapng file and produces a plain-English security report:

  - IP conversations (who talked to whom, and how much)
  - TCP 3-way handshakes (SYN -> SYN/ACK -> ACK), complete or incomplete
  - DNS queries and responses
  - HTTP requests/responses (method, host, path)
  - Unencrypted data exposure (plaintext HTTP, credentials in payloads)
  - Basic suspicious-pattern checks (port scans, unusual ports, plaintext
    auth submissions)

Usage:
    python scripts/analyze_pcap.py <path_to_pcap> [--json report.json]

This script only reads/parses a file you already have on disk. It does
not capture live traffic itself -- use Wireshark or tcpdump for that
(see docs/lab-guide.md).
"""

import argparse
import json
import re
import sys
from collections import defaultdict, Counter

from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw

CREDENTIAL_PATTERNS = [
    re.compile(rb"password\s*=", re.IGNORECASE),
    re.compile(rb"passwd\s*=", re.IGNORECASE),
    re.compile(rb"pwd\s*=", re.IGNORECASE),
    re.compile(rb"authorization:\s*basic", re.IGNORECASE),
    re.compile(rb"username\s*=", re.IGNORECASE),
]

COMMON_PLAINTEXT_PORTS = {
    21: "FTP",
    23: "Telnet",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
}


def load_packets(path):
    try:
        return rdpcap(path)
    except Exception as e:
        print(f"❌ Could not read pcap file: {e}", file=sys.stderr)
        sys.exit(1)


def analyze_ip_conversations(packets):
    convo_counts = Counter()
    for pkt in packets:
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            pair = tuple(sorted([src, dst]))
            convo_counts[pair] += 1
    return convo_counts


def analyze_tcp_handshakes(packets):
    """
    Tracks SYN -> SYN/ACK -> ACK sequences per (src_ip, src_port, dst_ip, dst_port)
    flow to determine which TCP sessions completed a proper 3-way handshake.
    """
    flows = defaultdict(lambda: {"SYN": False, "SYNACK": False, "ACK": False})

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            ip = pkt[IP]
            tcp = pkt[TCP]
            flags = tcp.flags

            if flags == "S":
                key = (ip.src, tcp.sport, ip.dst, tcp.dport)
                flows[key]["SYN"] = True
            elif flags == "SA":
                key = (ip.dst, tcp.dport, ip.src, tcp.sport)
                flows[key]["SYNACK"] = True
            elif flags == "A":
                key = (ip.src, tcp.sport, ip.dst, tcp.dport)
                if flows[key]["SYN"] and flows[key]["SYNACK"]:
                    flows[key]["ACK"] = True

    results = []
    for key, state in flows.items():
        # Skip noise: an ACK-only entry that never had a SYN attempt
        # associated with it (e.g. a later ACK in an unrelated direction,
        # like connection teardown) isn't a handshake attempt at all.
        if not state["SYN"] and not state["SYNACK"]:
            continue
        src_ip, src_port, dst_ip, dst_port = key
        complete = state["SYN"] and state["SYNACK"] and state["ACK"]
        results.append({
            "client": f"{src_ip}:{src_port}",
            "server": f"{dst_ip}:{dst_port}",
            "complete": complete,
            "steps": state,
        })
    return results


def analyze_dns(packets):
    records = []
    for pkt in packets:
        if DNS in pkt:
            dns = pkt[DNS]
            if dns.qr == 0 and dns.qd is not None:  # query
                qname = dns.qd.qname.decode(errors="replace").rstrip(".")
                records.append({
                    "type": "query",
                    "src": pkt[IP].src if IP in pkt else "?",
                    "domain": qname,
                })
            elif dns.qr == 1 and dns.an is not None:  # response
                qname = dns.qd.qname.decode(errors="replace").rstrip(".") if dns.qd else "?"
                answers = []
                an = dns.an
                for i in range(dns.ancount):
                    rr = an[i] if dns.ancount > 1 else an
                    rdata = rr.rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode(errors="replace")
                    answers.append(str(rdata))
                    if dns.ancount <= 1:
                        break
                records.append({
                    "type": "response",
                    "src": pkt[IP].src if IP in pkt else "?",
                    "domain": qname,
                    "answers": answers,
                })
    return records


def analyze_http(packets):
    http_events = []
    for i, pkt in enumerate(packets):
        if TCP in pkt and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            if payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ")):
                first_line = payload.split(b"\r\n", 1)[0].decode(errors="replace")
                host_match = re.search(rb"Host:\s*([^\r\n]+)", payload, re.IGNORECASE)
                host = host_match.group(1).decode(errors="replace") if host_match else "?"
                http_events.append({
                    "packet_index": i,
                    "direction": "request",
                    "summary": first_line,
                    "host": host,
                    "src": pkt[IP].src if IP in pkt else "?",
                    "dst": pkt[IP].dst if IP in pkt else "?",
                })
            elif payload.startswith(b"HTTP/"):
                first_line = payload.split(b"\r\n", 1)[0].decode(errors="replace")
                http_events.append({
                    "packet_index": i,
                    "direction": "response",
                    "summary": first_line,
                })
    return http_events


def analyze_unencrypted_exposure(packets):
    findings = []
    for i, pkt in enumerate(packets):
        if TCP in pkt and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            for pattern in CREDENTIAL_PATTERNS:
                if pattern.search(payload):
                    findings.append(
                        f"Plaintext credential-like field detected in packet #{i} "
                        f"(pattern: {pattern.pattern.decode(errors='replace')})"
                    )
                    break
        if TCP in pkt and pkt[TCP].dport in (80, 8080) and Raw in pkt:
            if bytes(pkt[Raw].load).startswith((b"GET ", b"POST ")):
                findings.append(
                    f"HTTP (unencrypted) traffic on packet #{i} — data is sent in cleartext, "
                    f"consider HTTPS instead"
                )
    return findings


def analyze_suspicious_patterns(packets):
    findings = []

    # Simple port-scan heuristic: one source IP hitting many distinct
    # destination ports on the same destination IP with SYN packets.
    syn_targets = defaultdict(set)
    for pkt in packets:
        if IP in pkt and TCP in pkt and pkt[TCP].flags == "S":
            syn_targets[(pkt[IP].src, pkt[IP].dst)].add(pkt[TCP].dport)

    for (src, dst), ports in syn_targets.items():
        if len(ports) >= 10:
            findings.append(
                f"Possible port scan: {src} sent SYN packets to {len(ports)} "
                f"different ports on {dst}"
            )

    # Plaintext service usage
    used_ports = set()
    for pkt in packets:
        if TCP in pkt:
            used_ports.add(pkt[TCP].dport)
    for port, name in COMMON_PLAINTEXT_PORTS.items():
        if port in used_ports:
            findings.append(f"Cleartext protocol in use: {name} (port {port})")

    return findings


def print_report(pcap_path, packets):
    print("=" * 60)
    print(" NETWORK TRAFFIC ANALYSIS REPORT")
    print("=" * 60)
    print(f"File: {pcap_path}")
    print(f"Total packets: {len(packets)}\n")

    print("--- IP CONVERSATIONS ---")
    convo_counts = analyze_ip_conversations(packets)
    if convo_counts:
        for (a, b), count in convo_counts.most_common():
            print(f"{a:<16} <-> {b:<16} |  {count} packets")
    else:
        print("(none found)")

    print("\n--- TCP HANDSHAKES DETECTED ---")
    handshakes = analyze_tcp_handshakes(packets)
    if handshakes:
        for idx, h in enumerate(handshakes, 1):
            status = "complete" if h["complete"] else "incomplete"
            print(f"[{idx}] {h['client']} -> {h['server']}   "
                  f"SYN({h['steps']['SYN']}) -> SYN/ACK({h['steps']['SYNACK']}) "
                  f"-> ACK({h['steps']['ACK']})  ({status})")
    else:
        print("(none found)")

    print("\n--- DNS ACTIVITY ---")
    dns_records = analyze_dns(packets)
    if dns_records:
        for rec in dns_records:
            if rec["type"] == "query":
                print(f"{rec['src']} asked for {rec['domain']}")
            else:
                print(f"{rec['src']} resolved {rec['domain']} -> {', '.join(rec['answers'])}")
    else:
        print("(none found)")

    print("\n--- HTTP TRAFFIC ---")
    http_events = analyze_http(packets)
    if http_events:
        for ev in http_events:
            if ev["direction"] == "request":
                print(f"[pkt #{ev['packet_index']}] {ev['summary']}   Host: {ev['host']}   "
                      f"({ev['src']} -> {ev['dst']})")
            else:
                print(f"[pkt #{ev['packet_index']}] {ev['summary']}")
    else:
        print("(none found)")

    print("\n--- ⚠️  UNENCRYPTED DATA EXPOSURE ---")
    exposure = analyze_unencrypted_exposure(packets)
    if exposure:
        for f in exposure:
            print(f"[!] {f}")
    else:
        print("(none found)")

    print("\n--- ⚠️  SUSPICIOUS PATTERN CHECKS ---")
    suspicious = analyze_suspicious_patterns(packets)
    if suspicious:
        for f in suspicious:
            print(f"[!] {f}")
    else:
        print("(no obvious suspicious patterns detected)")

    print("=" * 60)

    return {
        "file": pcap_path,
        "total_packets": len(packets),
        "ip_conversations": [{"pair": list(k), "count": v} for k, v in convo_counts.items()],
        "tcp_handshakes": handshakes,
        "dns_activity": dns_records,
        "http_traffic": http_events,
        "unencrypted_exposure": exposure,
        "suspicious_patterns": suspicious,
    }


def main():
    parser = argparse.ArgumentParser(description="Analyze a .pcap file for security-relevant traffic patterns.")
    parser.add_argument("pcap_file", help="Path to the .pcap/.pcapng file to analyze")
    parser.add_argument("--json", help="Optional path to also write the report as JSON", default=None)
    args = parser.parse_args()

    packets = load_packets(args.pcap_file)
    report = print_report(args.pcap_file, packets)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n📄 JSON report written to {args.json}")


if __name__ == "__main__":
    main()
