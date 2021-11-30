#!/usr/bin/env python3
from __future__ import absolute_import, unicode_literals

import argparse
import contextlib
from time import sleep

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

import util.trace
import util.vis

DEFAULT_IPS = ["8.8.4.4", "1.0.0.1", "9.9.9.9"]
ACCESSIBLE_ADDRESS = "www.example.com"
DEFAULT_BLOCKED_ADDRESS = "www.twitter.com"


def get_args():
    parser = argparse.ArgumentParser(description='trace DNS censorship')
    parser.add_argument('-p', '--prefix', action='store',
                        help="prefix for the graph file name")
    parser.add_argument('-i', '--ips', type=str,
                        help="add comma-separated IPs (up to 6)")
    parser.add_argument('-d', '--domain', type=str,
                        help="change the default blocked domain name")
    parser.add_argument('-g', '--graph', action='store_true',
                        help="no further TTL advance after reaching the endpoint")
    parser.add_argument('-a', '--attach', action='store_true',
                        help="attach VisJS javascript and CSS to the HTML file (work offline)")
    args = parser.parse_args()
    return args


def main(args):
    name_prefix = ""
    request_ips = DEFAULT_IPS
    blocked_address = DEFAULT_BLOCKED_ADDRESS
    accessible_address = ACCESSIBLE_ADDRESS
    just_graph = False
    attach_jscss = False
    request_ips = []
    if args.get("prefix"):
        name_prefix = args["prefix"] + "-dns"
    else:
        name_prefix = "dns"
    if args.get("ips"):
        request_ips = args["ips"].split(',')
    if args.get("domain"):
        blocked_address = args["domain"]
    if args.get("graph"):
        just_graph = True
    if args.get("attach"):
        attach_jscss = True
    dns_request_1 = IP(
        dst="1.1.1.1", id=1, ttl=1)/UDP(
        sport=53, dport=53)/DNS(
            rd=1, id=1, qd=DNSQR(qname=accessible_address))
    dns_request_2 = dns_request_1.copy()
    dns_request_2[DNSQR].qname = blocked_address
    was_successful, measurement_path = util.trace.trace_route(
        ip_list=request_ips, request_packet_1=dns_request_1,
        request_packet_2=dns_request_2, name_prefix=name_prefix,
        annotation_1=accessible_address, annotation_2=blocked_address,
        just_graph=just_graph)
    if was_successful:
        if util.vis.vis(measurement_path, attach_jscss):
            print("finished.")


if __name__ == "__main__":
    main(vars(get_args()))
