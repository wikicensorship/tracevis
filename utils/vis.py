#!/usr/bin/env python3

import ipaddress
import json
import os

import networkx as nx
from pyvis.network import Network

ROUTER_COLOR = "green"
WINDOWS_COLOR = "blue"
LINUX_COLOR = "purple"
MIDDLEBOX_COLOR = "red"
PEP_COLOR = "green"
NAT_COLOR = "dodgerblue"
NO_RESPONSE_COLOR = "gray"

ROUTER_NAME = "Router"
WINDOWS_NAME = "Windows"
LINUX_NAME = "Linux"
MIDDLEBOX_NAME = "Middlebox"
PEP_NAME = "PEP"
NAT_NAME = "NAT"
NO_RESPONSE_NAME = "unknown"

REQUEST_COLORS = [
    "DarkTurquoise", "HotPink", "LimeGreen", "Red", "DodgerBlue", "Orange",
    "MediumSlateBlue", "DarkGoldenrod", "Green", "Brown", "YellowGreen", "Magenta"
]


TEMPLATE_PATH = os.path.dirname(
    __file__) + "/templates/template_offline.html.jinja"

multi_directed_graph = nx.MultiDiGraph()


def get_packet_type(packet_obj):
    if len(packet_obj.keys()) > 1:
        return list(packet_obj.keys())[1]


def take_one_complement(chksum_int_value):
    complement_str = ''
    for ch in "{0:04x}".format(chksum_int_value):
        complement_str += ("{0:01x}".format(15 - int(ch, base=16)))
    return int(complement_str, base=16)


def calculate_chksum(ip_in_icmp, sent_ttl):
    # the word for checksum is hex of TTL and proto. i.e.: 0xttlproto
    # so each TTL worth 256
    sent_ttl_int = int(sent_ttl)
    received_chksum = ip_in_icmp['chksum']
    received_ttl_int = int(ip_in_icmp['ttl'])
    checksum_str = ''
    if sent_ttl_int > 1 and sent_ttl_int > received_ttl_int:
        corrected_ttl = sent_ttl_int - received_ttl_int
        remained_value = corrected_ttl * 256
        checksum_hex = take_one_complement(int(received_chksum, base=16))
        checksum_tmp = checksum_hex + remained_value
        max_chksum_value = 0xffff
        if checksum_tmp > max_chksum_value:
            checksum_tmp = (checksum_tmp & max_chksum_value) + \
                (checksum_tmp >> 16)
            if checksum_tmp > max_chksum_value:
                checksum_tmp = (checksum_tmp & max_chksum_value) + \
                    (checksum_tmp >> 16)
        checksum_str = hex(take_one_complement(checksum_tmp))
    else:
        checksum_str = received_chksum
    return checksum_str


def detect_nat_pep_middlebox(sent, received):
    is_nat = False
    is_middlebox = False
    is_pep = False
    packet_type = ""
    tcpflag = ""
    if not 'ICMP' in received[0].keys():
        # sent packet 1 = {}
        # received packets = [
        #                     {received packet 1},
        #                     {received packet 2},
        #                     {received packet 3}
        #                    ]
        if 'TCP' in received[0].keys():
            if len(received) > 1:
                if received[0]['TCP']['flags'] == "A" and 'ICMP' in received[1].keys():
                    is_pep = True
                    packet_type = get_packet_type(received[1])
                    ip_id_is_same = received[1]['IP in ICMP']['id'] == sent['IP']['id']
                    calculated_chksum = calculate_chksum(
                        received[1]['IP in ICMP'], sent['IP']['ttl'])
                    if calculated_chksum != sent['IP']['chksum'] and ip_id_is_same:
                        is_nat = True
                    if not ip_id_is_same:
                        is_pep = True  # todo xhdix: mark as $something else
                elif received[0]['TCP']['flags'] in ["R", "RA", "F", "FA"] and 'ICMP' in received[1].keys():
                    is_pep = True
                    is_middlebox = True
                    packet_type = get_packet_type(received[1])
                    ip_id_is_same = received[1]['IP in ICMP']['id'] == sent['IP']['id']
                    calculated_chksum = calculate_chksum(
                        received[1]['IP in ICMP'], sent['IP']['ttl'])
                    if calculated_chksum != sent['IP']['chksum'] and ip_id_is_same:
                        is_nat = True
                    if not ip_id_is_same:
                        is_pep = True  # todo xhdix: mark as $something else
                elif received[0]['TCP']['flags'] in ["R", "RA", "F", "FA"]:
                    packet_type = get_packet_type(received[0])
                    tcpflag = received[0]['TCP']['flags']
                    if received[0]['IP']['id'] == sent['IP']['id']:
                        is_middlebox = True
                else:
                    packet_type = get_packet_type(received[1])
                    if packet_type == 'TCP':
                        tcpflag = received[1]['TCP']['flags']
                    if received[1]['IP']['id'] == sent['IP']['id']:
                        is_middlebox = True
            # we need hello from server, not ACK from middlebox
            elif received[0]['TCP']['flags'] != "A":
                packet_type = get_packet_type(received[0])
                tcpflag = received[0]['TCP']['flags']
                if received[0]['IP']['id'] == sent['IP']['id']:
                    is_middlebox = True
            # here we just want to have a correct path, so we ignore the lack of ACK before Server Hello in some weird networks
            elif received[0]['TCP']['flags'] == "A" and 'Raw' in received[0].keys():
                packet_type = get_packet_type(received[0])
                tcpflag = received[0]['TCP']['flags']
                if received[0]['IP']['id'] == sent['IP']['id']:
                    is_middlebox = True
            else:
                is_pep = True
        else:
            packet_type = get_packet_type(received[0])
            if received[0]['IP']['id'] == sent['IP']['id']:
                is_middlebox = True
    else:
        packet_type = 'ICMP'
        ip_id_is_same = received[0]['IP in ICMP']['id'] == sent['IP']['id']
        calculated_chksum = calculate_chksum(
            received[0]['IP in ICMP'], sent['IP']['ttl'])
        if calculated_chksum != sent['IP']['chksum'] and ip_id_is_same:
            is_nat = True
        if not ip_id_is_same:
            is_pep = True  # todo xhdix: mark as $something else
    return is_nat, is_middlebox, is_pep, packet_type, tcpflag


def parse_ttl(response_ttl, current_ttl):
    device_color = ""
    backttl = 0
    is_middlebox = False
    device_os_name = ""
    if response_ttl <= 20:
        backttl = int((current_ttl - response_ttl) / 2) + 1
        device_color = MIDDLEBOX_COLOR
        is_middlebox = True
        device_os_name = MIDDLEBOX_NAME
    elif response_ttl <= 64:
        backttl = 64 - response_ttl + 1
        device_color = LINUX_COLOR
        device_os_name = LINUX_NAME
    elif response_ttl <= 128:
        backttl = 128 - response_ttl + 1
        device_color = WINDOWS_COLOR
        device_os_name = WINDOWS_NAME
    else:
        backttl = 255 - response_ttl + 1
        device_color = ROUTER_COLOR
        device_os_name = ROUTER_NAME
    return backttl, device_color, device_os_name, is_middlebox


def visualize(previous_node_id, current_node_id,
              current_node_label, current_node_title, device_color,
              current_edge_title, requset_color, current_edge_label,
              current_node_shape):
    if not multi_directed_graph.has_node(current_node_id):
        multi_directed_graph.add_node(current_node_id,
                                      label=current_node_label, color=device_color,
                                      title=current_node_title, shape=current_node_shape)
    multi_directed_graph.add_edge(previous_node_id, current_node_id, label=current_edge_label,
                                  color=requset_color, title=current_edge_title)


def tooltips_append_lines(is_nat, is_middlebox, is_pep, packet_type, tcpflag):
    append_line = ''
    if packet_type == "TCP":
        append_line = "<br/>response TCP flag: " + tcpflag
    return ("<br/>NAT: " + str(is_nat)
            + "<br/>Middlebox: " + str(is_middlebox)
            + "<br/>PEP: " + str(is_pep)
            + "<br/>response packet: " + packet_type
            + append_line)


def styled_tooltips(
        current_request_color, current_ttl_str, backttl, request_ip, elapsed_ms,
        packet_size, repeat_step, device_os_name, append_lines, annotation):
    time_size = "*"
    elapsed_ms_str = "*"
    packet_size_str = "*"
    if packet_size != "*":
        packet_size_str = str(packet_size) + "B"
    if elapsed_ms != "*":
        elapsed_ms_str = str(format(elapsed_ms, '.3f')) + "ms"
        time_size = str(format(elapsed_ms/packet_size, '.3f')) + "ms/B"
    tooltips_str = "<pre style=\"color:" + current_request_color
    tooltips_str += "\">TTL: " + current_ttl_str
    tooltips_str += "<br/>Back-TTL: " + backttl
    tooltips_str += "<br/>Request to: " + request_ip
    tooltips_str += "<br/>annotation: " + annotation
    tooltips_str += "<br/>Time: " + elapsed_ms_str
    tooltips_str += "<br/>Size: " + packet_size_str
    tooltips_str += "<br/>Time/Size: " + time_size
    tooltips_str += "<br/>OS: " + device_os_name
    tooltips_str += append_lines
    tooltips_str += "<br/>Repeat step: " + repeat_step + "</pre>"
    return tooltips_str


def already_reached_destination_str(previous_node_id, dst_addr_id):
    if dst_addr_id in previous_node_id:
        return True
    else:
        return False


def initialize_detected(length_all):
    nodes = []
    for _ in range(length_all):
        nodes.append({"is_nat": False, "is_middlebox": False, "is_pep": False})
    return nodes


def initialize_first_nodes_nx(src_addr, length_all):
    nodes = []
    for _ in range(length_all):
        nodes.append(str(src_addr))
    return nodes


def save_measurement_graph(graph_name, attach_jscss):
    net_vis = Network("1500px", "1500px",
                      directed=True, bgcolor="#eeeeee")
    net_vis.from_nx(multi_directed_graph)
    net_vis.set_edge_smooth('dynamic')
    if attach_jscss:
        net_vis.set_template(TEMPLATE_PATH)
    if graph_name.endswith(".json"):
        graph_name = graph_name[:-5]
    graph_path = graph_name + ".html"
    net_vis.save_graph(graph_path)
    print("saved: " + graph_path)


def vis(measurement_path, attach_jscss, edge_lable: str = "none"):
    all_measurements = []
    was_successful = False
    with open(measurement_path) as json_file:
        all_measurements = json.load(json_file)
    measurement_steps = 0
    src_addr = all_measurements[0]["src_addr"]
    src_addr_id = 'x' + str(int(ipaddress.IPv4Address(src_addr))) + 'x'
    multi_directed_graph.add_node(
        src_addr_id, label=src_addr, color="Chocolate", title="source address",
        shape="diamond")
    for measurement in all_measurements:
        dst_addr = measurement["dst_addr"]
        dst_addr_id = 'x' + str(int(ipaddress.IPv4Address(dst_addr))) + 'x'
        annotation = "-"
        if "annotation" in measurement.keys():
            annotation = measurement["annotation"]
        all_results = measurement["result"]
        results_repeat_length = len(all_results[0]["result"])
        previous_node_ids = initialize_first_nodes_nx(
            src_addr_id, results_repeat_length)
        already_detected = initialize_detected(results_repeat_length)
        for try_step in all_results:  # will be up to 255
            current_ttl = try_step["hop"]
            current_ttl_str = str(current_ttl)
            results = try_step["result"]
            repeat_steps = 0
            skip_next = False
            for result in results:
                if skip_next:
                    skip_next = False
                    continue
                not_yet_destination = not (already_reached_destination_str(
                    previous_node_ids[repeat_steps], dst_addr_id))
                if not_yet_destination:
                    if "late" in result.keys():
                        skip_next = True
                    current_node_label = "***"
                    current_edge_title = "***"
                    current_edge_label = ""
                    current_node_id = "0"
                    current_node_shape = "dot"
                    elapsed_ms = "*"
                    packet_size = "*"
                    backttl = "*"
                    device_color = NO_RESPONSE_COLOR
                    device_name = NO_RESPONSE_NAME
                    append_lines = ""
                    is_middlebox = False
                    if 'x' in result.keys():
                        current_node_id = (
                            "unknown" + previous_node_ids[repeat_steps] + "x")
                        if edge_lable != "none":
                            current_edge_label = "*"
                    else:
                        answer_ip = result["from"]
                        backttl, device_color, device_name, is_middlebox_ttl = parse_ttl(
                            result["ttl"], current_ttl)
                        if "rtt" in result.keys():
                            elapsed_ms = result["rtt"]
                        if edge_lable == "rtt":
                            if elapsed_ms != "*":
                                current_edge_label = format(elapsed_ms, '.3f')
                        elif edge_lable == "backttl":
                            current_edge_label = str(backttl)
                        current_node_id = 'x' + str(
                            int(ipaddress.IPv4Address(answer_ip))) + 'x'
                        if "packets" in result.keys():
                            if "received" in result['packets'].keys():
                                if len(result['packets']['received']) != 0:
                                    is_nat, is_middlebox, is_pep, packet_type, tcpflag = detect_nat_pep_middlebox(
                                        result['packets']['sent'], result['packets']['received']
                                    )
                                    if (is_middlebox_ttl or is_middlebox
                                            ) and not already_detected[repeat_steps]["is_middlebox"]:
                                        pass  # we decide about it later
                                    elif is_pep and not already_detected[repeat_steps]["is_pep"]:
                                        device_color = PEP_COLOR
                                        device_name = PEP_NAME
                                        current_node_shape = "star"
                                        already_detected[repeat_steps]["is_pep"] = True
                                        current_node_id = "pep" + current_node_id + "x"
                                    elif is_nat and not already_detected[repeat_steps]["is_nat"]:
                                        device_color = NAT_COLOR
                                        device_name = NAT_NAME
                                        already_detected[repeat_steps]["is_nat"] = True
                                        current_node_id = "nat" + current_node_id + "x"
                                    append_lines = tooltips_append_lines(
                                        is_nat, is_middlebox, is_pep, packet_type, tcpflag)
                                    if (is_middlebox_ttl or is_middlebox):
                                        already_detected[repeat_steps]["is_middlebox"] = True
                                    if is_pep:
                                        already_detected[repeat_steps]["is_pep"] = True
                                    if is_nat:
                                        already_detected[repeat_steps]["is_nat"] = True
                        if is_middlebox_ttl or is_middlebox:
                            current_node_id = "middlebox" + current_node_id + "x"
                            current_node_shape = "star"
                            device_color = MIDDLEBOX_COLOR
                            device_name = MIDDLEBOX_NAME
                            already_detected[repeat_steps]["is_middlebox"] = True
                        elif current_node_id == dst_addr_id:
                            current_node_shape = "square"
                        current_node_label = answer_ip
                        packet_size = result["size"]
                    repeat_step_str = str(repeat_steps + 1)
                    current_edge_title = styled_tooltips(
                        current_request_color=(
                            REQUEST_COLORS[measurement_steps]),
                        current_ttl_str=current_ttl_str, backttl=str(backttl),
                        request_ip=dst_addr, elapsed_ms=elapsed_ms,
                        packet_size=packet_size, repeat_step=repeat_step_str,
                        device_os_name=device_name, append_lines=append_lines,
                        annotation=annotation
                    )
                    visualize(
                        previous_node_ids[repeat_steps], current_node_id,
                        current_node_label, device_name, device_color,
                        current_edge_title, REQUEST_COLORS[measurement_steps],
                        current_edge_label, current_node_shape
                    )
                    previous_node_ids[repeat_steps] = current_node_id
                repeat_steps += 1
        measurement_steps += 1
    print("saving measurement graph...")
    save_measurement_graph(measurement_path, attach_jscss)
    print("· · · - · -     · · · - · -     · · · - · -     · · · - · -")
