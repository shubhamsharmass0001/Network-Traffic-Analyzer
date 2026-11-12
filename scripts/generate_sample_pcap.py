#!/usr/bin/env python3
"""
generate_sample_pcap.py
------------------------
Generates a small, entirely SYNTHETIC .pcap file containing example
traffic patterns (TCP 3-way handshake, a DNS query/response, and a
plaintext HTTP request with a fake login form submission).

This is built with Scapy purely in memory/offline -- no real network
traffic is sent or captured. It exists so this repo can safely ship a
sample capture on GitHub (real captures should never be committed,
since they can contain private IPs/credentials) and so the analyzer
script has something to run against out of the box.

Usage:
    python scripts/generate_sample_pcap.py
"""

from scapy.all import (
    Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap
)
import os

OUTPUT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "sample_captures", "sample_traffic.pcap"
)

CLIENT_IP = "192.168.1.50"
SERVER_IP = "93.184.216.34"   # example.com's documented example IP block
DNS_SERVER_IP = "8.8.8.8"
CLIENT_MAC = "aa:bb:cc:00:11:22"
SERVER_MAC = "aa:bb:cc:00:33:44"


def build_dns_query_response():
    """A DNS query for example.com and its response."""
    query = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=DNS_SERVER_IP)
        / UDP(sport=5353, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )
    response = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=DNS_SERVER_IP, dst=CLIENT_IP)
        / UDP(sport=53, dport=5353)
        / DNS(
            qr=1, aa=0, rd=1, ra=1,
            qd=DNSQR(qname="example.com"),
            an=DNSRR(rrname="example.com", ttl=300, rdata=SERVER_IP),
        )
    )
    return [query, response]


def build_tcp_handshake(sport=52344, dport=80):
    """A textbook TCP 3-way handshake: SYN, SYN/ACK, ACK."""
    syn = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=sport, dport=dport, flags="S", seq=1000)
    )
    syn_ack = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001)
    )
    ack = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
    )
    return [syn, syn_ack, ack]


def build_http_request(sport=52344, dport=80):
    """
    A deliberately INSECURE plaintext HTTP POST, to illustrate the kind
    of unencrypted-data-exposure finding the analyzer script looks for.
    All values here are fake/example placeholders.
    """
    http_payload = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 35\r\n"
        b"\r\n"
        b"username=demo_user&password=hunter2"
    )
    req = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=2001)
        / Raw(load=http_payload)
    )

    http_response_payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: 20\r\n"
        b"\r\n"
        b"<html>Welcome</html>"
    )
    resp = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(sport=dport, dport=sport, flags="PA", seq=2001, ack=1001 + len(http_payload))
        / Raw(load=http_response_payload)
    )
    return [req, resp]


def build_fin():
    fin = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=52344, dport=80, flags="FA", seq=2000, ack=3000)
    )
    fin_ack = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(sport=80, dport=52344, flags="A", seq=3000, ack=2001)
    )
    return [fin, fin_ack]


def main():
    packets = []
    packets += build_dns_query_response()
    packets += build_tcp_handshake()
    packets += build_http_request()
    packets += build_fin()

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    wrpcap(OUTPUT_PATH, packets)
    print(f"✅ Wrote {len(packets)} synthetic packets to {os.path.abspath(OUTPUT_PATH)}")
    print("This file is 100% offline-generated and safe to commit to GitHub.")


if __name__ == "__main__":
    main()
