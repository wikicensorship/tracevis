#!/usr/bin/env python3
from __future__ import absolute_import, unicode_literals

import argparse
import contextlib
import ipaddress
import json
import urllib.request
from datetime import datetime
from time import sleep

import networkx as nx
from pyvis.network import Network

ROUTER_COLOR = "green"
WINDOWS_COLOR = "blue"
LINUX_COLOR = "purple"
MIDDLEBOX_COLOR = "red"
NO_RESPONSE_COLOR = "gray"
DEVICE_NAME = {ROUTER_COLOR: "Router", WINDOWS_COLOR: "Windows",
               LINUX_COLOR: "Linux", MIDDLEBOX_COLOR: "Middlebox", NO_RESPONSE_COLOR: "unknown"}
REQUEST_COLORS = ["DarkTurquoise", "HotPink", "LimeGreen", "Red", "DodgerBlue", "Orange",
                  "MediumSlateBlue", "DarkGoldenrod", "Green", "Brown", "YellowGreen", "Magenta"]

MEASUREMENT_IDS = [
    5011,  # c.root-servers.net
    5013,  # e.root-servers.net
    5004,  # f.root-servers.net
    5005,  # i.root-servers.net
    5001,  # k.root-servers.net
    5008,  # l.root-servers.net
    5006,  # m.root-servers.net
    5005,  # topology4.dyndns.atlas.ripe.net
    5151  # topology4.dyndns.atlas.ripe.net
]

MULTI_DIRECTED_GRAPH = nx.MultiDiGraph()


def parse_ttl(response_ttl, current_ttl):
    device_color = ""
    backttl = 0
    if response_ttl <= 20:
        backttl = int((current_ttl - response_ttl) / 2) + 1
        device_color = MIDDLEBOX_COLOR
    elif response_ttl <= 64:
        backttl = 64 - response_ttl + 1
        device_color = LINUX_COLOR
    elif response_ttl <= 128:
        backttl = 128 - response_ttl + 1
        device_color = WINDOWS_COLOR
    else:
        backttl = 255 - response_ttl + 1
        device_color = ROUTER_COLOR
    return backttl, device_color


def visualize(previous_node_id, current_node_id,
              current_node_label, current_node_title, device_color,
              current_edge_title, requset_color, current_edge_label):
    if not MULTI_DIRECTED_GRAPH.has_node(current_node_id):
        MULTI_DIRECTED_GRAPH.add_node(current_node_id,
                                      label=current_node_label, color=device_color,
                                      title=current_node_title)
    MULTI_DIRECTED_GRAPH.add_edge(previous_node_id, current_node_id, label=current_edge_label,
                                  color=requset_color, title=current_edge_title)


def styled_tooltips(current_request_colors, current_ttl_str, backttl, request_ip,
                    elapsed_ms, packet_size, repeat_all_steps):
    time_size = "*"
    elapsed_ms_str = "*"
    packet_size_str = "*"
    if packet_size != "*":
        packet_size_str = str(packet_size) + "B"
    if elapsed_ms != "*":
        elapsed_ms_str = str(format(elapsed_ms, '.3f')) + "ms"
        time_size = str(format(elapsed_ms/packet_size, '.3f')) + "ms/B"
    return ("<pre style=\"color:" + current_request_colors
            + "\">TTL: " + current_ttl_str
            + "<br/>Back-TTL: " + backttl
            + "<br/>Request to: " + request_ip
            + "<br/>Time: " + elapsed_ms_str
            + "<br/>Size: " + packet_size_str
            + "<br/>Time/Size: " + time_size
            + "<br/>Repeat step: " + str(repeat_all_steps) + "</pre>")


def initialize_first_nodes(src_addr):
    nodes = []
    for _ in range(10):
        nodes.append(str(src_addr))
    return nodes


def get_args():
    parser = argparse.ArgumentParser(description='trace route of a packet')
    parser.add_argument('-p', '--prefix', action='store',
                        help="prefix for the graph file name")
    parser.add_argument('-i', '--id', type=str,
                        help="probe ID")
    parser.add_argument('-f', '--file', type=str,
                        help=" open a measurement file")
    args = parser.parse_args()
    return args


def main(args):
    all_measurements = []
    probe_id = ""
    graph_name = ""
    if args.get("id"):
        probe_id = str(args["id"])
    if args.get("prefix"):
        graph_name = args["prefix"] + "-ripe-atlas-" + probe_id + "-traceroute-graph-" \
            + datetime.utcnow().strftime("%Y%m%d-%H%M")
    else:
        graph_name = "ripe-" + probe_id + "-traceroute-graph-" \
            + datetime.utcnow().strftime("%Y%m%d-%H%M")
    if probe_id != "":
        print(
            " ********************************************************************** ")
        print(
            "downloading data from probe ID: " + str(probe_id))
        print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
        for measurement_id in MEASUREMENT_IDS:
            print(
                "downloading measurement ID: " + str(measurement_id))
            requset_url = ("https://atlas.ripe.net/api/v2/measurements/" 
                + str(measurement_id)
                + "/latest/?format=json&probe_ids="
                + str(probe_id)
            )
            with urllib.request.urlopen(requset_url) as url:
                downloaded_data = json.loads(url.read().decode())
            if downloaded_data is not None:
                all_measurements.append(downloaded_data[0])
                print(
                    "downloading measurement ID " + str(measurement_id) + " finished.")
            else:
                print("failed to download measurement ID: "
                    + str(measurement_id))
            sleep(3)
            print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
        print(
            " ********************************************************************** ")
        if len(all_measurements) < 1:
            exit()
        print("saving json file to: " + graph_name + ".json")
        with open((graph_name + ".json"), 'w', encoding='utf-8') as json_file:
            json.dump(all_measurements, json_file, ensure_ascii=False, indent=4)
        print(
            " ********************************************************************** ")
    elif args.get("file"):
        with open(args["file"]) as json_file:
            all_measurements = json.load(json_file)
    measurement_steps = 0
    src_addr = all_measurements[0]["src_addr"]
    src_addr_id = str(int(ipaddress.IPv4Address(src_addr)))
    MULTI_DIRECTED_GRAPH.add_node(
        src_addr_id, label=src_addr, color="Chocolate", title="source address")
    for measurement in all_measurements:
        previous_node_ids = initialize_first_nodes(src_addr_id)
        dst_addr = measurement["dst_addr"]
        dst_addr_id = str(int(ipaddress.IPv4Address(dst_addr)))
        all_results = measurement["result"]
        for try_step in all_results:  # will be up to 255
            current_ttl = try_step["hop"]
            current_ttl_str = str(current_ttl)
            results = try_step["result"]
            repeat_steps = 0
            skip_next = False
            for result in results:  # will be up to 3
                if skip_next:
                    skip_next = False
                    continue
                if "late" in result.keys():
                    skip_next = True
                current_node_label = ""
                current_edge_title = ""
                current_edge_label = ""
                current_node_id = "0"
                if 'x' in result.keys():
                    current_node_id = (
                        "unknown" + previous_node_ids[repeat_steps] + "x" + current_ttl_str)
                    current_node_label = "***"
                    current_edge_title = "***"
                    current_edge_label = "*"
                    device_color = NO_RESPONSE_COLOR
                    elapsed_ms = "*"
                    packet_size = "*"
                else:
                    answer_ip = result["from"]
                    backttl, device_color = parse_ttl(
                        result["ttl"], current_ttl)
                    if "rtt" in result.keys():
                        elapsed_ms = result["rtt"]
                        current_edge_label = str(format(elapsed_ms, '.3f'))
                    else:
                        elapsed_ms = "*"
                        current_edge_label = "*"
                    current_node_id = str(
                        int(ipaddress.IPv4Address(answer_ip)))
                    if device_color == MIDDLEBOX_COLOR:
                        current_node_id = (
                            "middlebox" + str(current_node_id) + "x")
                    current_node_label = answer_ip
                    current_edge_title = str(backttl)
                    packet_size = result["size"]
                current_edge_title = styled_tooltips(
                    REQUEST_COLORS[measurement_steps], current_ttl_str,
                    current_edge_title, dst_addr, elapsed_ms,
                    packet_size, (repeat_steps + 1))
                visualize(
                    previous_node_ids[repeat_steps], current_node_id,
                    current_node_label, DEVICE_NAME[device_color], device_color,
                    current_edge_title, REQUEST_COLORS[measurement_steps], current_edge_label
                )
                previous_node_ids[repeat_steps] = current_node_id
                repeat_steps += 1
        measurement_steps += 1
    net_vis = Network("1500px", "1500px", directed=True, bgcolor="#eeeeee")
    net_vis.from_nx(MULTI_DIRECTED_GRAPH)
    net_vis.set_edge_smooth('dynamic')
    net_vis.show(graph_name + ".html")


if __name__ == "__main__":
    main(vars(get_args()))
