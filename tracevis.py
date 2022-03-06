#!/usr/bin/env python3
from __future__ import absolute_import, unicode_literals

import argparse
import os
import platform

import utils.csv
import utils.dns
import utils.packet_input
import utils.ripe_atlas
import utils.trace
import utils.vis

TIMEOUT = 1
MAX_TTL = 50
DEFAULT_OUTPUT_DIR = "./tracevis_data/"
DEFAULT_REQUEST_IPS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
OS_NAME = platform.system()


def get_args():
    parser = argparse.ArgumentParser(
        description='Traceroute with any packet. \
            Visualize the routes. Discover Middleboxes and Firewalls')
    parser.add_argument('-n', '--name', action='store',
                        help="prefix for the graph file name")
    parser.add_argument('-i', '--ips', type=str,
                        help="add comma-separated IPs (up to 6 for two packet and up to 12 for one packet)")
    parser.add_argument('-p', '--packet', action='store_true',
                        help="receive one or two packets from the IP layer via the terminal input and trace route with")
    parser.add_argument('--dns', action='store_true',
                        help="trace route with a simple DNS over UDP packet")
    parser.add_argument('--dnstcp', action='store_true',
                        help="trace route with a simple DNS over TCP packet")
    parser.add_argument('-c', '--continue', action='store_true',
                        help="further TTL advance after reaching the endpoint (up to max ttl)")
    parser.add_argument('-m', '--maxttl', type=int,
                        help="set max TTL (up to 255, default: 50)")
    parser.add_argument('-t', '--timeout', type=int,
                        help="set timeout in seconds for each request (default: 1 second)")
    parser.add_argument('-R', '--ripe', type=str,
                        help="download the latest traceroute measuremets of a RIPE Atlas probe via ID and visualize")
    parser.add_argument('-I', '--ripemids', type=str,
                        help="add comma-separated RIPE Atlas measurement IDs (up to 12)")
    parser.add_argument('-f', '--file', type=str,
                        help="open a measurement file and visualize")
    parser.add_argument('--csv', action='store_true',
                        help="create a sorted csv file instead of visualization")
    parser.add_argument('--csvraw', action='store_true',
                        help="create a raw csv file instead of visualization")
    parser.add_argument('-a', '--attach', action='store_true',
                        help="attach VisJS javascript and CSS to the HTML file (work offline)")
    parser.add_argument('-l', '--label', type=str,
                        help="set edge label: none, rtt, backttl. (default: backttl)")
    parser.add_argument('--domain1', type=str,
                        help="change the default accessible domain name (dns trace)")
    parser.add_argument('-d', '--domain2', type=str,
                        help="change the default blocked domain name (dns trace)")
    parser.add_argument('--annot1', type=str,
                        help="annotation for the first packets (dns and packet trace)")
    parser.add_argument('--annot2', type=str,
                        help="annotation for the second packets (dns and packet trace)")
    parser.add_argument('--rexmit', action='store_true',
                        help="same as rexmit option (only one packet. all TTL steps, same stream)")
    parser.add_argument('-o', '--options', type=str, default="new",
                        help="change the behavior of the trace route" 
                            + " - 'rexmit' : to be similar to doing retransmission with incremental TTL (only one packet, one destination)"
                            + " - 'new' : to change source port, sequence number, etc in each request (default)"
                            + " - 'new,rexmit' : to begin with the 'new' option in each of the three steps for all destinations and then rexmit"
                        )
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
    do_tcph1 = False
    packet_2 = None
    annotation_2 = ""
    do_tcph2 = False
    blocked_address = ""
    accessible_address = ""
    do_traceroute = False
    was_successful = False
    measurement_path = ""
    edge_lable = "backttl"
    trace_retransmission = False
    trace_with_retransmission = False
    output_dir = os.getenv('TRACEVIS_OUTPUT_DIR', DEFAULT_OUTPUT_DIR)
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    if args.get("name"):
        name_prefix = args["name"] + "-"
    if args.get("ips"):
        request_ips = args["ips"].replace(' ', '').split(',')
    if args.get("domain1"):
        accessible_address = args["domain1"]
    if args.get("domain2"):
        blocked_address = args["domain2"]
    if args.get("continue"):
        continue_to_max_ttl = True
    if args.get("maxttl"):
        max_ttl = args["maxttl"]
    if args.get("timeout"):
        timeout = args["timeout"]
    if args.get("attach"):
        attach_jscss = True
    if args.get("annot1"):
        annotation_1 = args["annot1"]
    if args.get("annot2"):
        annotation_2 = args["annot2"]
    if args.get("label"):
        edge_lable = args["label"].lower()
    if args.get("rexmit"):
        trace_retransmission = True
    if args.get("options"):
        trace_options= args["ips"].replace(' ', '').split(',')
        if "new" in trace_options and "rexmit" in trace_options:
            trace_with_retransmission = True
        elif "rexmit" in trace_options:
            trace_retransmission = True
        else:
            pass # "new" is default
    if args.get("dns") or args.get("dnstcp"):
        do_traceroute = True
        name_prefix += "dns"
        packet_1, annotation_1, packet_2, annotation_2 = utils.dns.get_dns_packets(
            blocked_address=blocked_address, accessible_address=accessible_address,
            dns_over_tcp=(args["dnstcp"]))
        if len(request_ips) == 0:
            request_ips = DEFAULT_REQUEST_IPS
    if args.get("packet") or args.get("rexmit"):
        do_traceroute = True
        name_prefix += "packet"
        packet_1, packet_2, do_tcph1, do_tcph2 = utils.packet_input.copy_input_packets(
            OS_NAME, trace_retransmission)
        if do_tcph1 or do_tcph2:
            name_prefix += "-tcph"
    if trace_with_retransmission:
        name_prefix += "-newrexmit"
    if do_traceroute:
        was_successful, measurement_path = utils.trace.trace_route(
            ip_list=request_ips, request_packet_1=packet_1, output_dir=output_dir,
            max_ttl=max_ttl, timeout=timeout,
            request_packet_2=packet_2, name_prefix=name_prefix,
            annotation_1=annotation_1, annotation_2=annotation_2,
            continue_to_max_ttl=continue_to_max_ttl,
            do_tcph1=do_tcph1, do_tcph2=do_tcph2,
            trace_retransmission=trace_retransmission,
            trace_with_retransmission=trace_with_retransmission)
    if args.get("ripe"):
        measurement_ids = ""
        if args.get("ripemids"):
            measurement_ids = args["ripemids"].replace(' ', '').split(',')
        name_prefix = name_prefix + "ripe-atlas"
        was_successful, measurement_path = utils.ripe_atlas.download_from_atlas(
            probe_id=args["ripe"], output_dir=output_dir, name_prefix=name_prefix,
            measurement_ids=measurement_ids)
    if args.get("file"):
        measurement_path = args["file"]
        if args.get("csv"):
            utils.csv.json2csv(measurement_path)
        elif args.get("csvraw"):
            utils.csv.json2csv(measurement_path, False)
        else:
            was_successful = True
    if was_successful:
        if utils.vis.vis(
                measurement_path=measurement_path, attach_jscss=attach_jscss,
                edge_lable=edge_lable):
            print("finished.")


if __name__ == "__main__":
    main(vars(get_args()))
