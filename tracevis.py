#!/usr/bin/env python3
from __future__ import absolute_import, unicode_literals

import argparse
import json
import os
import platform
import sys
import textwrap
from copy import deepcopy

import utils.csv
import utils.dns
import utils.packet_input
import utils.ripe_atlas
import utils.trace
import utils.vis

TIMEOUT = 1
MAX_TTL = 50
REPEAT_REQUESTS = 3
DEFAULT_OUTPUT_DIR = "./tracevis_data/"
DEFAULT_REQUEST_IPS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
OS_NAME = platform.system()


def dump_args_to_file(file, args, packet_info):
    args_without_config_arg = args.copy()
    if 'config_file' in args_without_config_arg:
        del args_without_config_arg['config_file']
    if packet_info:
        args_without_config_arg['packet_data'] = packet_info.as_dict()
        args_without_config_arg['packet_input_method'] = 'json'
    with open(file, 'w') as f:
        json.dump(args_without_config_arg, f, indent=4, sort_keys=True)


def process_input_args(args, parser):
    cli_args_dict = vars(args)
    passed_args = {
        opt.dest
        for opt in parser._option_string_actions.values()
        if hasattr(args, opt.dest) and opt.default != getattr(args, opt.dest)
    }
    args_dict = cli_args_dict.copy()
    if args.config_file:
        with open(args.config_file) as f:
            args_dict.update(json.load(f))
    for k in passed_args:
        args_dict[k] = cli_args_dict.get(k)
    if 'dns' in passed_args:
        args_dict['packet'] = False
        args_dict['packet_input_method'] = None
    if 'packet' in passed_args:
        args_dict['dns'] = False
    return args_dict


def get_args():
    parser = argparse.ArgumentParser(
        description='Traceroute with any packet. \
            Visualize the routes. Discover Middleboxes and Firewalls', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--config-file', type=str, default=None,
                        help='Load configuration from file'),
    parser.add_argument('-n', '--name', action='store',
                        help="prefix for the graph file name")
    parser.add_argument('-i', '--ips', type=str,
                        help="add comma-separated IPs (up to 6 for two packet and up to 12 for one packet)")
    parser.add_argument('-p', '--packet', action='store_true',
                        help="receive one or two packets from the IP layer via the terminal input and trace route with")
    parser.add_argument('--packet-input-method', dest='packet_input_method', choices=['json', 'hex', 'interactive'], default="hex",
                        help=textwrap.dedent("""Select packet input method 
- json: load packet data from a json/file(set via --packet-data)
- hex: paste hex dump of packet into interactive shell 
- interactive: use full featured scapy and python console to craft packet\n\n"""))
    parser.add_argument("--packet-data", dest='packet_data', type=str,
                        help="Packet json data if input method is 'json' (use @file to load from file)", default=None)
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
    parser.add_argument('-r', '--repeat', type=int,
                        help="set the number of repetitions of each request (default: 3 steps)")
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
    parser.add_argument('--paris', action='store_true',
                        help="same as 'new,rexmit' option (like Paris-Traceroute)")
    # this argument ('-o', '--options') will be changed or removed before v1.0.0
    parser.add_argument('-o', '--options', type=str, default="new",
                        help=""" (this argument will be changed or removed before v1.0.0)
change the behavior of the trace route 
- 'rexmit' : to be similar to doing retransmission with incremental TTL (only one packet, one destination)
- 'new' : to change source port, sequence number, etc in each request (default)
- 'new,rexmit' : to begin with the 'new' option in each of the three steps for all destinations and then rexmit"""
                        )
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()
    args_dict = process_input_args(args, parser)
    return args_dict


def main(args):
    if args.get('packet_data') and isinstance(args.get('packet_data'), str):
        if args.get('packet_data')[0] == '@':
            with open(args.get('packet_data')[1:]) as f:
                args['packet_data'] = json.load(f)
        else:
            args['packet_data'] = json.loads(args.get('packet_data'))
    input_packet = None
    name_prefix = ""
    continue_to_max_ttl = False
    max_ttl = MAX_TTL
    timeout = TIMEOUT
    repeat_requests = REPEAT_REQUESTS
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
    if args.get("repeat"):
        repeat_requests = args["repeat"]
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
    if args.get("paris"):
        trace_with_retransmission = True
    if args.get("options"):
        # this argument will be changed or removed before v1.0.0
        trace_options = args["options"].replace(' ', '').split(',')
        if "new" in trace_options and "rexmit" in trace_options:
            trace_with_retransmission = True
        elif "rexmit" in trace_options:
            trace_retransmission = True
        else:
            pass  # "new" is default
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
        try:
            if args.get('packet_input_method') == 'json':
                input_packet = utils.packet_input.InputPacketInfo.from_json(
                    OS_NAME, trace_retransmission, packet_data=deepcopy(
                        args.get('packet_data'))
                )
            elif args.get('packet_input_method') == 'interactive':
                input_packet = utils.packet_input.InputPacketInfo.from_scapy(
                    OS_NAME, trace_retransmission)
            elif args.get('packet_input_method') == 'hex':
                input_packet = utils.packet_input.InputPacketInfo.from_stdin(
                    OS_NAME, trace_retransmission)
            else:
                raise RuntimeError("Bad input type")
        except (utils.packet_input.BADPacketException, utils.packet_input.FirewallException) as e:
            print(f"{e!s}")
            exit(1)
        except Exception as e:
            print(f"Error!\n{e!s}")
            exit(2)
        if do_tcph1 or do_tcph2:
            name_prefix += "-tcph"
    if trace_with_retransmission:
        name_prefix += "-paristr"
    if do_traceroute:
        if args.get("packet") or args.get("rexmit"):
            with input_packet as ctx:
                packet_1, packet_2, do_tcph1, do_tcph2 = ctx
        was_successful, measurement_path, no_internet = utils.trace.trace_route(
            ip_list=request_ips, request_packet_1=packet_1, output_dir=output_dir,
            max_ttl=max_ttl, timeout=timeout, repeat_requests=repeat_requests,
            request_packet_2=packet_2, name_prefix=name_prefix,
            annotation_1=annotation_1, annotation_2=annotation_2,
            continue_to_max_ttl=continue_to_max_ttl,
            do_tcph1=do_tcph1, do_tcph2=do_tcph2,
            trace_retransmission=trace_retransmission,
            trace_with_retransmission=trace_with_retransmission)
        if no_internet:
            attach_jscss = True
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
        config_dump_file_name = f"{os.path.splitext(measurement_path)[0]}.conf"
        dump_args_to_file(config_dump_file_name, args, input_packet)
        if utils.vis.vis(
                measurement_path=measurement_path, attach_jscss=attach_jscss,
                edge_lable=edge_lable):
            print("finished.")


if __name__ == "__main__":
    main(get_args())
