#!/usr/bin/env python3
from __future__ import absolute_import, unicode_literals

import contextlib
import json
import os
import time
from datetime import datetime
from socket import socket
from time import sleep

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.sendrecv import sr1
from scapy.volatile import RandShort

from util.traceroute_struct import Traceroute

#from scapy.arch import get_if_addr
#from scapy.interfaces import conf

LOCALHOST = '127.0.0.1'
SLEEP_TIME = 1
TIMEOUT = 1
MAX_TTL = 50
have_2_packet = False
measurement_data = [[], []]
OUTPUT_DIR = "./output/"


def parse_packet(req_answer, current_ttl, elapsed_ms):
    if req_answer is not None:
        backttl = 0
        if req_answer[IP].ttl <= 20:
            backttl = int((current_ttl - req_answer[IP].ttl) / 2) + 1
        elif req_answer[IP].ttl <= 64:
            backttl = 64 - req_answer[IP].ttl + 1
        elif req_answer[IP].ttl <= 128:
            backttl = 128 - req_answer[IP].ttl + 1
        else:
            backttl = 255 - req_answer[IP].ttl + 1
        print("   <<< answer:"
              + "   ip.src: " + req_answer[IP].src
              + "   ip.ttl: " + str(req_answer[IP].ttl)
              + "   back-ttl: " + str(backttl))
        answer_summary = req_answer.summary()
        print("      " + answer_summary)
        print("· − · · · rtt: " + str(elapsed_ms)+ "ms · · · − · ")
        return req_answer[IP].src, elapsed_ms, len(req_answer), req_answer[IP].ttl, answer_summary
    else:
        print("              *** no response *** ")
        print("· − · · · rtt: " + str(elapsed_ms) + "ms · · · · · · · · timeout ")
        return "***", elapsed_ms, 0, 0, "*"


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


def send_packet(request_packet, request_ip, current_ttl):
    this_request = request_packet
    this_request[IP].dst = request_ip
    this_request[IP].ttl = current_ttl
    this_request[IP].id = RandShort()
    if this_request.haslayer(TCP):
        this_request[TCP].sport = ephemeral_port_reserve()
        del(this_request[TCP].chksum)
    elif this_request.haslayer(UDP):
        this_request[UDP].sport = RandShort()
        del(this_request[UDP].chksum)
    if this_request.haslayer(DNS):
        this_request.id = RandShort()
    del(this_request[IP].len)
    del(this_request[IP].chksum)
    print(">>>request:"
          + "   ip.dst: " + this_request[IP].dst
          + "   ip.ttl: " + str(current_ttl))
    start_time = time.perf_counter()
    req_answer = sr1(this_request, verbose=0, timeout=TIMEOUT)
    end_time = time.perf_counter()
    elapsed_ms = float(format(abs((end_time - start_time) * 1000), '.3f'))
    return parse_packet(req_answer, current_ttl, elapsed_ms)


def already_reached_destination(previous_node_id, current_node_ip):
    if previous_node_id == current_node_ip:
        return True
    else:
        return False


def are_equal(original_list, result_list):
    counter = 0
    for item in original_list:
        original_item = item
        reault_item_1 = result_list[0][counter]
        if reault_item_1 != original_item:
            return False
        if have_2_packet:
            reault_item_2 = result_list[1][counter]
            if reault_item_2 != original_item:
                return False
        counter += 1
    return True


def initialize_first_nodes(request_ips):
    nodes = []
    for _ in request_ips:
        nodes.append(LOCALHOST)
    if have_2_packet:
        return [nodes, nodes.copy()]
    else:
        return [nodes]


def initialize_json_first_nodes(
        request_ips, annotation_1, annotation_2, packet_1_proto, packet_2_proto):
    # source_address = get_if_addr(conf.iface) #todo: xhdix
    source_address = LOCALHOST
    start_time = int(datetime.utcnow().timestamp())
    for request_ip in request_ips:
        measurement_data[0].append(
            Traceroute(
                dst_addr=request_ip, annotation=annotation_1,
                src_addr=source_address, proto=packet_1_proto, timestamp=start_time
            )
        )
        if have_2_packet:
            measurement_data[1].append(
                Traceroute(
                    dst_addr=request_ip, annotation=annotation_2,
                    src_addr=source_address, proto=packet_2_proto, timestamp=start_time
                )
            )


def get_proto(request_packets):
    if (request_packets[0]).haslayer(TCP):
        packet_1_proto = "TCP"
    elif (request_packets[0]).haslayer(UDP):
        packet_1_proto = "UDP"
    elif(request_packets[0]).haslayer(ICMP):
        packet_1_proto = "ICMP"
    if have_2_packet:
        if (request_packets[1]).haslayer(TCP):
            packet_2_proto = "TCP"
        elif (request_packets[1]).haslayer(UDP):
            packet_2_proto = "UDP"
        elif(request_packets[1]).haslayer(ICMP):
            packet_2_proto = "ICMP"
        return packet_1_proto, packet_2_proto
    else:
        return packet_1_proto, ""


def save_measurement_data(request_ips, measurement_name, continue_to_max_ttl):
    end_time = int(datetime.utcnow().timestamp())
    measurement_data_json = []
    ip_steps = 0
    while ip_steps < len(request_ips):
        measurement_data[0][ip_steps].set_endtime(end_time)
        if not continue_to_max_ttl:
            measurement_data[0][ip_steps].clean_extra_result()
        measurement_data_json.append(measurement_data[0][ip_steps])
        if have_2_packet:
            measurement_data[1][ip_steps].set_endtime(end_time)
            if not continue_to_max_ttl:
                measurement_data[1][ip_steps].clean_extra_result()
            measurement_data_json.append(measurement_data[1][ip_steps])
        ip_steps += 1
    data_path = OUTPUT_DIR + measurement_name + ".json"
    with open(data_path, "a") as jsonfile:
        jsonfile.write(json.dumps(measurement_data_json,
                       default=lambda o: o.__dict__, indent=4))
    print("saved: " + data_path)
    return data_path


def trace_route(
        ip_list, request_packet_1, request_packet_2: str = "", name_prefix: str = "",
        annotation_1: str = "", annotation_2: str = "", continue_to_max_ttl: bool = False,
        max_ttl: int = MAX_TTL):
    measurement_name = ""
    request_packets = []
    was_successful = False
    global have_2_packet
    if request_packet_1 is None or len(ip_list) < 1:
        print("failed")  # todo: xhdix
        exit()
    if request_packet_2 == "":
        request_packets.append(request_packet_1)
        have_2_packet = False
    else:
        request_packets.append(request_packet_1)
        request_packets.append(request_packet_2)
        have_2_packet = True
    request_ips = ip_list
    if name_prefix != "":
        measurement_name = name_prefix + "-tracevis-" + \
            datetime.utcnow().strftime("%Y%m%d-%H%M")
    else:
        measurement_name = "tracevis-" + datetime.utcnow().strftime("%Y%m%d-%H%M")
    repeat_all_steps = 0
    packet_1_proto, packet_2_proto = get_proto(request_packets)
    initialize_json_first_nodes(
        request_ips=request_ips, annotation_1=annotation_1, annotation_2=annotation_2,
        packet_1_proto=packet_1_proto, packet_2_proto=packet_2_proto
    )
    if not os.path.exists(OUTPUT_DIR):
        os.mkdir(OUTPUT_DIR)
    print("− · − · −     − · − · −     − · − · −     − · − · −")
    while repeat_all_steps < 3:
        repeat_all_steps += 1
        previous_node_ids = initialize_first_nodes(request_ips)
        for current_ttl in range(1, max_ttl):
            if not continue_to_max_ttl and are_equal(request_ips, previous_node_ids):
                ip_steps = 0
                access_block_steps = 0
                while ip_steps < len(request_ips):
                    # to avoid confusing the order of results when we have already reached our destination
                    measurement_data[access_block_steps][ip_steps].add_hop(
                        current_ttl, "", 0, 0, 0, ""
                    )
                    ip_steps += 1
                    if have_2_packet and ip_steps == len(request_ips) and access_block_steps == 0:
                        ip_steps = 0
                        access_block_steps = 1
            else:
                ip_steps = 0
                access_block_steps = 0
                print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
                while ip_steps < len(request_ips):
                    sleep_time = SLEEP_TIME
                    not_yet_destination = not (already_reached_destination(
                        previous_node_ids[access_block_steps][ip_steps],
                        request_ips[ip_steps]))
                    if not continue_to_max_ttl:
                        if not_yet_destination:
                            answer_ip, elapsed_ms, packet_size, req_answer_ttl, answer_summary = send_packet(
                                request_packets[access_block_steps], request_ips[ip_steps],
                                current_ttl)
                            measurement_data[access_block_steps][ip_steps].add_hop(
                                current_ttl, answer_ip, elapsed_ms, packet_size, req_answer_ttl, answer_summary
                            )
                        else:
                            sleep_time = 0
                            # to avoid confusing the order of results when we have already reached our destination
                            measurement_data[access_block_steps][ip_steps].add_hop(
                                current_ttl, "", 0, 0, 0, ""
                            )
                    else:
                        answer_ip, elapsed_ms, packet_size, req_answer_ttl, answer_summary = send_packet(
                            request_packets[access_block_steps], request_ips[ip_steps],
                            current_ttl)
                        measurement_data[access_block_steps][ip_steps].add_hop(
                            current_ttl, answer_ip, elapsed_ms, packet_size, req_answer_ttl, answer_summary
                        )
                    if not_yet_destination:
                        if answer_ip == "***":
                            sleep_time = 0
                        previous_node_ids[access_block_steps][ip_steps] = answer_ip
                    print(
                        " · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
                    sleep(sleep_time)
                    ip_steps += 1
                    if have_2_packet and ip_steps == len(request_ips) and access_block_steps == 0:
                        ip_steps = 0
                        access_block_steps = 1
                        print(
                            " ********************************************************************** ")
                print(
                    " ********************************************************************** ")
                print(
                    " ********************************************************************** ")
                print(
                    " ********************************************************************** ")
    was_successful = True
    print("saving measurement data...")
    data_path = save_measurement_data(
        request_ips, measurement_name, continue_to_max_ttl)
    print("· · · − · −     · · · − · −     · · · − · −     · · · − · −")
    return(was_successful, data_path)
