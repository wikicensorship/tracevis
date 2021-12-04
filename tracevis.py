#!/usr/bin/env python3
from __future__ import absolute_import, unicode_literals

import argparse
from time import sleep

import util.dns
import util.packet_input
import util.ripe_atlas
import util.trace
import util.vis

TIMEOUT = 1
MAX_TTL = 50


def get_args():
    parser = argparse.ArgumentParser(description='trace DNS censorship')
    parser.add_argument('-n', '--name', action='store',
                        help="prefix for the graph file name")
    parser.add_argument('-i', '--ips', type=str,
                        help="add comma-separated IPs (up to 6)")
    parser.add_argument('--domain1', type=str,
                        help="change the default accessible domain name")
    parser.add_argument('-d', '--domain2', type=str,
                        help="change the default blocked domain name")
    parser.add_argument('-c', '--continue', action='store_true',
                        help="further TTL advance after reaching the endpoint (up to max ttl)")
    parser.add_argument('-m', '--maxttl', type=int,
                        help="set max TTL (up to 255, default: 50)")
    parser.add_argument('-t', '--timeout', type=int,
                        help="set timeout in seconds for each request (default: 1 second)")
    parser.add_argument('--dns', action='store_true',
                        help="send simple DNS over UDP packet")
    parser.add_argument('--dnstcp', action='store_true',
                        help="send simple DNS over TCP packet")
    parser.add_argument('-a', '--attach', action='store_true',
                        help="attach VisJS javascript and CSS to the HTML file (work offline)")
    parser.add_argument('-p', '--packet', action='store_true',
                        help="receive packets from the IP layer via the terminal input and send")
    parser.add_argument('--annot1', action='store_true',
                        help="annotation for the first packets")
    parser.add_argument('--annot2', action='store_true',
                        help="annotation for the second packets")
    parser.add_argument('-r', '--ripe', type=str,
                        help="ID of RIPE Atlas probe")
    parser.add_argument('-f', '--file', type=str,
                        help=" open a measurement file")
    args = parser.parse_args()
    return args


def main(args):
    name_prefix = ""
    continue_to_max_ttl = False
    max_ttl = MAX_TTL
    timeout = TIMEOUT
    attach_jscss = False
    request_ips = []
    packet_1 = None
    annotation_1 = ""
    packet_2 = None
    annotation_2 = ""
    blocked_address = ""
    accessible_address = ""
    do_traceroute = False
    was_successful = False
    measurement_path = ""
    if args.get("name"):
        name_prefix = args["name"]
    if args.get("ips"):
        request_ips = args["ips"].split(',')
    if args.get("domain1"):
        accessible_address = args["domain1"]
    if args.get("domain2"):
        blocked_address = args["domain2"]
    if args.get("continue"):
        continue_to_max_ttl = True
    if args.get("maxttl"):
        max_ttl =  args["maxttl"]
    if args.get("timeout"):
        timeout = args["timeout"]
    if args.get("attach"):
        attach_jscss = True
    if args.get("annot1"):
        annotation_1 = args["annot1"]
    if args.get("annot2"):
        annotation_2 = args["annot2"]
    if args.get("dns") or args.get("dnstcp"):
        do_traceroute = True
        packet_1, annotation_1, packet_2, annotation_2 = util.dns.get_dns_packets(
            blocked_address=blocked_address, accessible_address=accessible_address,
            dns_over_tcp=(args["dnstcp"]))
        if len(request_ips)  == 0:
            request_ips = ["1.1.1.1", "8.8.8.8", "9.9.9.9"] 
    if args.get("packet"):
        do_traceroute = True
        packet_1, packet_2 = util.packet_input.copy_input_packets()
    if do_traceroute:
        was_successful, measurement_path = util.trace.trace_route(
            ip_list=request_ips, request_packet_1=packet_1,
            max_ttl=max_ttl, timeout=timeout,
            request_packet_2=packet_2, name_prefix=name_prefix,
            annotation_1=annotation_1, annotation_2=annotation_2,
            continue_to_max_ttl=continue_to_max_ttl)
    if args.get("ripe"):
        was_successful, measurement_path = util.ripe_atlas.download_from_atlas(
            probe_id=args["ripe"])
    if args.get("file"):
        was_successful = True
        measurement_path = args["file"]
    if was_successful:
        if util.vis.vis(measurement_path, attach_jscss):
            print("finished.")


if __name__ == "__main__":
    main(vars(get_args()))
