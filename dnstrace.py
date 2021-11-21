#!/usr/bin/env python3
from __future__ import absolute_import, unicode_literals

import argparse
import contextlib
import ipaddress
from datetime import datetime
from socket import SO_REUSEADDR, SOL_SOCKET
from socket import socket
from time import sleep

import networkx as nx
from pyvis.network import Network
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1
from scapy.volatile import RandShort

LOCALHOST = '127.0.0.1'

SLEEP_TIME = 1
TIMEOUT = 1
ROUTER_COLOR = "green"
WINDOWS_COLOR = "blue"
LINUX_COLOR = "purple"
MIDDLEBOX_COLOR = "red"
NO_RESPONSE_COLOR = "gray"
DEVICE_NAME = {ROUTER_COLOR: "Router", WINDOWS_COLOR: "Windows",
               LINUX_COLOR: "Linux", MIDDLEBOX_COLOR: "Middlebox", NO_RESPONSE_COLOR: "unknown"}
ACCESSIBLE_REQUEST_COLORS = ["DarkTurquoise", "LimeGreen", "DodgerBlue",
                             "MediumSlateBlue", "Green", "YellowGreen"]
BLOCKED_REQUEST_COLORS = ["HotPink", "Red",
                          "Orange", "DarkGoldenrod", "Brown", "Magenta"]

DEFAULT_IPS = ["8.8.4.4", "1.0.0.1", "9.9.9.9"]
ACCESSIBLE_ADDRESS = "www.example.com"
DEFAULT_BLOCKED_ADDRESS = "www.twitter.com"

MULTI_DIRECTED_GRAPH = nx.MultiDiGraph()
MULTI_DIRECTED_GRAPH.add_node(
    1, label="this device", color="Chocolate", title="start")


def parse_packet(req_answer, current_ttl):
    device_color = ""
    if req_answer is not None:
        backttl = 0
        if req_answer[IP].ttl <= 20:
            backttl = int((current_ttl - req_answer[IP].ttl) / 2) + 1
            device_color = MIDDLEBOX_COLOR
        elif req_answer[IP].ttl <= 64:
            backttl = 64 - req_answer[IP].ttl + 1
            device_color = LINUX_COLOR
        elif req_answer[IP].ttl <= 128:
            backttl = 128 - req_answer[IP].ttl + 1
            device_color = WINDOWS_COLOR
        else:
            backttl = 255 - req_answer[IP].ttl + 1
            device_color = ROUTER_COLOR
        print("   <<< answer:"
              + "   ip.src: " + req_answer[IP].src
              + "   ip.ttl: " + str(req_answer[IP].ttl)
              + "   back-ttl: " + str(backttl))
        print("      " + req_answer.summary())
        return req_answer[IP].src, backttl, device_color
    else:
        print(" *** no response *** ")
        return "***", "***", NO_RESPONSE_COLOR

# ephemeral_port_reserve() function is based on https://github.com/Yelp/ephemeral-port-reserve


def ephemeral_port_reserve():
    with contextlib.closing(socket()) as s:
        s.bind((LOCALHOST, 0))
        # the connect below deadlocks on kernel >= 4.4.0 unless this arg is greater than zero
        s.listen(1)
        sockname = s.getsockname()
        # these three are necessary just to get the port into a TIME_WAIT state
        with contextlib.closing(socket()) as s2:
            s2.connect(sockname)
            sock, _ = s.accept()
            with contextlib.closing(sock):
                return sockname[1]


def send_packet(request_ip, current_ttl, request_address):
    dns_request = IP(
        dst=request_ip, id=RandShort(), ttl=current_ttl)/UDP(
        sport=ephemeral_port_reserve(), dport=53)/DNS(
            rd=1, id=RandShort(), qd=DNSQR(qname=request_address))
    print(">>>request:"
          + "   ip.dst: " + dns_request[IP].dst
          + "   ip.ttl: " + str(current_ttl))
    req_answer = sr1(dns_request, verbose=0, timeout=TIMEOUT)
    return parse_packet(req_answer, current_ttl)


def visualize(previous_node_id, current_node_id,
              current_node_label, current_node_title, device_color,
              current_edge_title, requset_color):
    if not MULTI_DIRECTED_GRAPH.has_node(current_node_id):
        MULTI_DIRECTED_GRAPH.add_node(current_node_id,
                                      label=current_node_label, color=device_color,
                                      title=current_node_title)
    MULTI_DIRECTED_GRAPH.add_edge(previous_node_id, current_node_id,
                                  color=requset_color, title=current_edge_title)


def already_reached_destination(previous_node_id, current_node_ip, access_block_steps, ip_steps):
    if previous_node_id in {str(int(ipaddress.IPv4Address(current_node_ip))),
                            (str(int(ipaddress.IPv4Address(current_node_ip)))
                            + "0000" + str(access_block_steps) + str(ip_steps))}:
        return True
    else:
        return False


def are_equal(original_list, result_list):
    counter = 0
    for item in original_list:
        original_item = str(int(ipaddress.IPv4Address(item)))
        original_item_middlebox = original_item + "0000"
        reault_item_1 = str(result_list[0][counter])
        reault_item_2 = str(result_list[1][counter])
        if reault_item_1 != original_item and not reault_item_1.startswith(
                original_item_middlebox):
            return False
        if reault_item_2 != original_item and not reault_item_2.startswith(
                original_item_middlebox):
            return False
        counter += 1
    return True


def initialize_first_nodes(request_ips):
    nodes = []
    for _ in request_ips:
        nodes.append(1)
    return nodes


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
    args = parser.parse_args()
    return args


def main(args):
    graph_name = ""
    request_ips = DEFAULT_IPS
    blocked_address = DEFAULT_BLOCKED_ADDRESS
    just_graph = False
    request_ips = []
    if args.get("prefix"):
        graph_name = args["prefix"] + "-dns-graph-" + \
            datetime.utcnow().strftime("%Y%m%d-%H%M")
    else:
        graph_name = "dns-graph-" + datetime.utcnow().strftime("%Y%m%d-%H%M")
    if args.get("ips"):
        request_ips = args["ips"].split(',')
    if args.get("domain"):
        blocked_address = args["domain"]
    if args.get("graph"):
        just_graph = True
    repeat_all_steps = 0
    while repeat_all_steps < 3:
        repeat_all_steps += 1
        previous_node_ids = [
            initialize_first_nodes(request_ips), initialize_first_nodes(request_ips)]
        for current_ttl in range(1, 30):
            if just_graph and are_equal(request_ips, previous_node_ids):
                break
            request_address = ACCESSIBLE_ADDRESS
            current_request_colors = ACCESSIBLE_REQUEST_COLORS
            ip_steps = 0
            access_block_steps = 0
            print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
            while ip_steps < len(request_ips):
                sleep_time = SLEEP_TIME
                not_yet_destination = not (already_reached_destination(
                    previous_node_ids[access_block_steps][ip_steps],
                    request_ips[ip_steps], access_block_steps, ip_steps))
                if just_graph:
                    if not_yet_destination:
                        answer_ip, backttl, device_color = send_packet(
                            request_ips[ip_steps], current_ttl, request_address)
                    else:
                        sleep_time = 0
                else:
                    answer_ip, backttl, device_color = send_packet(
                        request_ips[ip_steps], current_ttl, request_address)
                if not_yet_destination:
                    current_node_label = ""
                    current_edge_title = ""
                    current_node_id = "0"
                    current_ttl_str = str(current_ttl)
                    if answer_ip != "***":
                        current_node_id = str(
                            int(ipaddress.IPv4Address(answer_ip)))
                        if device_color == MIDDLEBOX_COLOR:
                            current_node_id = (
                                str(current_node_id) + "0000" + str(access_block_steps) + str(ip_steps))
                        current_node_label = answer_ip
                        current_edge_title = str(backttl)
                    else:
                        current_node_id = (
                            str(previous_node_ids[access_block_steps][ip_steps]) + "1111" + current_ttl_str)
                        current_node_label = "***"
                        current_edge_title = "***"
                        sleep_time = 0
                    current_edge_title = "TTL: " + current_ttl_str + \
                        " - " + "BackTTL: " + current_edge_title
                    visualize(previous_node_ids[access_block_steps][ip_steps], current_node_id,
                              current_node_label, DEVICE_NAME[device_color], device_color,
                              current_edge_title, current_request_colors[ip_steps])
                    previous_node_ids[access_block_steps][ip_steps] = current_node_id
                print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
                sleep(sleep_time)
                ip_steps += 1
                if ip_steps == len(request_ips) and access_block_steps == 0:
                    request_address = blocked_address
                    current_request_colors = BLOCKED_REQUEST_COLORS
                    ip_steps = 0
                    access_block_steps = 1
                    print(
                        " ********************************************************************** ")
            net_vis = Network("1500px", "1500px",
                              directed=True, bgcolor="#eeeeee")
            net_vis.from_nx(MULTI_DIRECTED_GRAPH)
            net_vis.set_edge_smooth('dynamic')
            net_vis.save_graph(graph_name + ".html")
            print(
                " ********************************************************************** ")
            print(
                " ********************************************************************** ")
            print(
                " ********************************************************************** ")
    net_vis = Network("1500px", "1500px", directed=True, bgcolor="#eeeeee")
    net_vis.from_nx(MULTI_DIRECTED_GRAPH)
    net_vis.set_edge_smooth('dynamic')
    net_vis.show(graph_name + ".html")


if __name__ == "__main__":
    main(vars(get_args()))
