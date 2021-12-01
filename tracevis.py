#!/usr/bin/env python3
from __future__ import absolute_import, unicode_literals

import argparse
from time import sleep

import util.dns
import util.packet_input
import util.ripe_atlas
import util.trace
import util.vis


def get_args():
    parser = argparse.ArgumentParser(description='trace DNS censorship')
    parser.add_argument('-n', '--name', action='store',
                        help="prefix for the graph file name")
    parser.add_argument('-i', '--ips', type=str,
                        help="add comma-separated IPs (up to 6)")
    parser.add_argument('-d', '--domain', type=str,
                        help="change the default blocked domain name")
    parser.add_argument('-g', '--graph', action='store_true',
                        help="no further TTL advance after reaching the endpoint")
    parser.add_argument('--dns', action='store_true',
                        help="send DNS packet")
    parser.add_argument('-a', '--attach', action='store_true',
                        help="attach VisJS javascript and CSS to the HTML file (work offline)")
    parser.add_argument('-p', '--packet', action='store_true',
                        help="receive packets from the IP layer via the terminal input and send")
    parser.add_argument('--annotation1', action='store_true',
                        help="annotation for the first packets")
    parser.add_argument('--annotation2', action='store_true',
                        help="annotation for the second packets")
    parser.add_argument('-r', '--ripe', type=str,
                        help="ID of RIPE Atlas probe")
    parser.add_argument('-f', '--file', type=str,
                        help=" open a measurement file")
    args = parser.parse_args()
    return args


def main(args):
    name_prefix = ""
    just_graph = False
    attach_jscss = False
    request_ips = []
    packet_1 = None
    annotation_1 = ""
    packet_2 = None
    annotation_2 = ""
    do_traceroute = False
    was_successful = False
    measurement_path = ""
    if args.get("name"):
        name_prefix = args["name"] + "-dns"
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
    if args.get("annotation1"):
        annotation_1 = args["annotation1"]
    if args.get("annotation2"):
        annotation_2 = args["annotation2"]
    if args.get("dns"):
        do_traceroute = True
        packet_1, annotation_1, packet_2, annotation_2 = util.dns.get_dns_packets()
    if args.get("packet"):
        do_traceroute = True
        packet_1, packet_2 = util.packet_input.copy_input_packets()
    if do_traceroute:
        was_successful, measurement_path = util.trace.trace_route(
            ip_list=request_ips, request_packet_1=packet_1,
            request_packet_2=packet_2, name_prefix=name_prefix,
            annotation_1=annotation_1, annotation_2=annotation_2,
            just_graph=just_graph)
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
