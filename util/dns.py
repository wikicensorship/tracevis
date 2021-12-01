#!/usr/bin/env python3
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

ACCESSIBLE_ADDRESS = "www.example.com"
DEFAULT_BLOCKED_ADDRESS = "www.twitter.com"


def get_dns_packets(blocked_address: str = "", accessible_address: str = ""):
    if blocked_address == "":
        blocked_address = DEFAULT_BLOCKED_ADDRESS
    if accessible_address == "":
        accessible_address = ACCESSIBLE_ADDRESS
    dns_request_1 = IP(
        dst="1.1.1.1", id=1, ttl=1)/UDP(
        sport=53, dport=53)/DNS(
            rd=1, id=1, qd=DNSQR(qname=accessible_address))
    dns_request_2 = dns_request_1.copy()
    dns_request_2[DNSQR].qname = blocked_address
    return dns_request_1, accessible_address, dns_request_2, blocked_address
