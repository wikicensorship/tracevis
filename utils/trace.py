#!/usr/bin/env python3
from __future__ import absolute_import, unicode_literals

import contextlib
import json
import platform
import socket
import sys
import time
from datetime import datetime
from time import sleep

from scapy.all import conf, get_if_addr
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.sendrecv import send, sr, sr1
from scapy.volatile import RandInt, RandShort

from utils.traceroute_struct import traceroute_data

SOURCE_IP_ADDRESS = get_if_addr(conf.iface)
LOCALHOST = '127.0.0.1'
SLEEP_TIME = 1
have_2_packet = False
measurement_data = [[], []]
OS_NAME = platform.system()


def parse_packet(request_and_answer, current_ttl, elapsed_ms):
    if request_and_answer is not None:
        req_answer = request_and_answer[1]
        packet_send_time = request_and_answer[0].sent_time
        packet_receive_time = req_answer.time
        packet_elapsed_ms = float(
            format(abs((packet_receive_time - packet_send_time) * 1000), '.3f'))
        if packet_elapsed_ms > 0:
            elapsed_ms = packet_elapsed_ms
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
        print("· - · · · rtt: " + str(elapsed_ms) + "ms · · · - · ")
        return req_answer[IP].src, elapsed_ms, len(req_answer), req_answer[IP].ttl, answer_summary
    else:
        print("              *** no response *** ")
        print("· - · · · rtt: " + str(elapsed_ms) +
              "ms · · · · · · · · timeout ")
        return "***", elapsed_ms, 0, 0, "*"


# ephemeral_port_reserve() function is based on https://github.com/Yelp/ephemeral-port-reserve


def ephemeral_port_reserve(proto: str = "tcp"):
    socketkind = socket.SOCK_STREAM
    ipproto = socket.IPPROTO_TCP
    if proto == "udp":
        socketkind = socket.SOCK_DGRAM
        ipproto = socket.IPPROTO_UDP
    with contextlib.closing(socket.socket(socket.AF_INET, socketkind, ipproto)) as s:
        s.bind((SOURCE_IP_ADDRESS, 0))
        # the connect below deadlocks on kernel >= 4.4.0 unless this arg is greater than zero
        if proto == "tcp":
            s.listen(1)
        sockname = s.getsockname()
        # these three are necessary just to get the port into a TIME_WAIT state
        with contextlib.closing(socket.socket(socket.AF_INET, socketkind, ipproto)) as s2:
            s2.connect(sockname)
            if proto == "tcp":
                sock, _ = s.accept()
                with contextlib.closing(sock):
                    return sockname[1]
            with contextlib.closing(s2):
                return sockname[1]


def tcp_options_correction(tcp_options, new_timestamp, syn_ack_timestamp):
    new_options = []
    default_timestamp = ('Timestamp', (new_timestamp, syn_ack_timestamp))
    for attr in tcp_options:
        if 'Timestamp' == str(attr[0]):
            new_options.append(default_timestamp)
        else:
            new_options.append(attr)
    return new_options


def generate_syn_tcp_options(new_timestamp):
    if OS_NAME == "Linux":
        tcp_options = [('MSS', 1460), ('SAckOK', b''),
                       ('Timestamp', (new_timestamp, 0)), ('NOP', None), ('WScale', 7)]
        return tcp_options
    elif OS_NAME == "Windows":
        tcp_options = [('MSS', 1460), ('NOP', None),
                       ('NOP', None), ('SAckOK', b'')]
        return tcp_options
    elif OS_NAME == "Darwin":
        tcp_options = [('MSS', 1460), ('NOP', None), ('WScale', 6), ('NOP', None),
                       ('NOP', None), ('Timestamp', (new_timestamp, 0)), ('SAckOK', b''), ('EOL', None)]
        return tcp_options
    else:
        return []


def generate_ack_tcp_options(new_timestamp, syn_ack_timestamp):
    if OS_NAME == "Linux" or OS_NAME == "Darwin":
        tcp_options = [('NOP', None), ('NOP', None),
                       ('Timestamp', (new_timestamp, syn_ack_timestamp))]
        return tcp_options
    else:
        return []


def get_timestamp(tcp_options):
    default_timestamp = 0
    for attr in tcp_options:
        if 'Timestamp' == str(attr[0]):
            default_timestamp = attr[1][0]
    return default_timestamp


def get_new_timestamp():
    timestamp_now = time.time()
    return timestamp_now, (int(timestamp_now) ^ int(RandInt()))


def send_packet_with_tcphandshake(this_request, timeout):
    timestamp_start, new_timestamp = get_new_timestamp()
    ip_address = this_request[IP].dst
    destination_port = this_request[TCP].dport
    syn_tcp_options = generate_syn_tcp_options(new_timestamp)
    ans = []
    max_repeat = 0
    # here we are trying to do a new TCP handshake every time because
    # we are trying to trace packet data, not SYN packet. And
    # we know about intermittent stream blocking
    while len(ans) == 0 and max_repeat < 5:
        source_port = ephemeral_port_reserve("tcp")
        send_syn = IP(
            dst=ip_address, id=RandShort())/TCP(
            sport=source_port, dport=destination_port, seq=RandInt(), flags="S", options=syn_tcp_options)
        tcp_handshake_timeout = timeout + max_repeat
        ans, unans = sr(send_syn, verbose=0, timeout=tcp_handshake_timeout)
        if len(ans) == 0:
            print("Warning: No response to SYN packet yet")
        max_repeat += 1
    if len(ans) == 0:
        print("Error: doing TCP handshake failed "
              + str(max_repeat)
              + " times. You should test with PingVis instead")  # todo: xhdix
        sleep(timeout + max_repeat)  # double sleep (￣o￣) . z Z.
        return ans, unans
    else:
        timeout += 2  # we should wait more for data packets.
        syn_ack_timestamp = get_timestamp(ans[0][1][TCP].options)
        new_timestamp = new_timestamp + \
            int((time.time() - timestamp_start) * 1000)
        ack_tcp_options = generate_ack_tcp_options(
            new_timestamp, syn_ack_timestamp)
        send_ack = IP(
            dst=ip_address, id=(ans[0][0][IP].id + 1))/TCP(
            sport=source_port, dport=destination_port, seq=ans[0][1][TCP].ack,
            ack=ans[0][1][TCP].seq + 1, flags="A", options=ack_tcp_options)
        send(send_ack, verbose=0)
        send_data = this_request
        del(send_data[IP].src)
        send_data[IP].id = ans[0][0][IP].id + 2
        send_data[TCP].sport = source_port
        send_data[TCP].seq = ans[0][1][TCP].ack
        send_data[TCP].ack = ans[0][1][TCP].seq + 1
        send_data[TCP].options = tcp_options_correction(
            send_data[TCP].options, new_timestamp, syn_ack_timestamp)
        del(send_data[TCP].chksum)
        del(send_data[IP].len)
        del(send_data[IP].chksum)
        request_and_answers, unanswered = sr(
            send_data, verbose=0, timeout=timeout, multi=True)
        # send_fin = send_ack.copy() # todo: xhdix
        # send_fin[IP].id=ans[0][0][IP].id + 1
        # send_fin[TCP].flags = "FA"
        # send(send_fin, verbose=0)
        # send_last_ack=send_fin.copy()
        # send_last_ack[IP].id=send_fin[IP].id + 1
        # send_last_ack[TCP].flags = "A"
        # send(send_last_ack, verbose=0)
        return request_and_answers, unanswered


def send_single_packet(this_request, timeout):
    this_request[IP].id = RandShort()
    if this_request.haslayer(TCP):
        this_request[TCP].sport = ephemeral_port_reserve("tcp")
        if this_request[TCP].flags == "S":
            this_request[TCP].seq = RandInt()
        timestamp_start, new_timestamp = get_new_timestamp()
        this_request[TCP].options = tcp_options_correction(
            this_request[TCP].options, new_timestamp, int(timestamp_start))
        del(this_request[TCP].chksum)
    elif this_request.haslayer(UDP):
        this_request[UDP].sport = ephemeral_port_reserve("udp")
        del(this_request[UDP].len)
        del(this_request[UDP].chksum)
    if this_request.haslayer(DNS):
        this_request.id = RandShort()
    del(this_request[IP].len)
    del(this_request[IP].chksum)
    request_and_answers, unanswered = sr(
        this_request, verbose=0, timeout=timeout)
    return request_and_answers, unanswered


def retransmission_single_packet(this_request, timeout):
    this_request[IP].id += 1
    del(this_request[IP].chksum)
    request_and_answers, unanswered = sr(
        this_request, verbose=0, timeout=timeout)
    return request_and_answers, unanswered


def send_packet(request_packet, request_ip, current_ttl, timeout, do_tcphandshake, trace_retransmission):
    this_request = request_packet
    del(this_request[IP].src)
    this_request[IP].dst = request_ip
    this_request[IP].ttl = current_ttl
    print(">>>request:"
          + "   ip.dst: " + request_ip
          + "   ip.ttl: " + str(current_ttl))
    request_and_answers = []
    unanswered = []
    start_time = time.perf_counter()
    if do_tcphandshake:
        request_and_answers, unanswered = send_packet_with_tcphandshake(
            this_request, timeout)
    elif trace_retransmission:
        request_and_answers, unanswered = retransmission_single_packet(
            this_request, timeout)
    else:
        request_and_answers, unanswered = send_single_packet(
            this_request, timeout)
    end_time = time.perf_counter()
    elapsed_ms = float(format(abs((end_time - start_time) * 1000), '.3f'))
    if do_tcphandshake:
        sleep(timeout)  # double sleep (￣o￣) . z Z. maybe we should wait more
    if len(request_and_answers) == 0:
        return parse_packet(None, current_ttl, elapsed_ms)
    else:
        if do_tcphandshake and not request_and_answers[0][1].haslayer(ICMP):
            request_and_answers.show()
            if len(request_and_answers) > 1:
                if request_and_answers[0][1][TCP].flags == "A" and request_and_answers[1][1].haslayer(ICMP):
                    print("first answer is from middlebox (╯°□°)╯︵ ┻━┻")
                    return parse_packet(request_and_answers[1], current_ttl, elapsed_ms)
                else:
                    return parse_packet(request_and_answers[1], current_ttl, elapsed_ms)
            else:
                # we need PA from server, not ACK from middlebox
                return parse_packet(None, current_ttl, elapsed_ms)
        else:
            return parse_packet(request_and_answers[0], current_ttl, elapsed_ms)


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
        nodes.append(SOURCE_IP_ADDRESS)
    if have_2_packet:
        return [nodes, nodes.copy()]
    else:
        return [nodes]


def initialize_json_first_nodes(
        request_ips, annotation_1, annotation_2, packet_1_proto, packet_2_proto,
        packet_1_port, packet_2_port):
    # source_address = get_if_addr(conf.iface) #todo: xhdix
    source_address = SOURCE_IP_ADDRESS
    start_time = int(datetime.utcnow().timestamp())
    for request_ip in request_ips:
        measurement_data[0].append(
            traceroute_data(
                dst_addr=request_ip, annotation=annotation_1,
                src_addr=source_address, proto=packet_1_proto, port=packet_1_port,
                timestamp=start_time
            )
        )
        if have_2_packet:
            measurement_data[1].append(
                traceroute_data(
                    dst_addr=request_ip, annotation=annotation_2,
                    src_addr=source_address, proto=packet_2_proto, port=packet_2_port,
                    timestamp=start_time
                )
            )


def get_packets_info(request_packets):
    packet_1_proto = ""
    packet_2_proto = ""
    packet_1_port = -1
    packet_2_port = -1
    if (request_packets[0]).haslayer(IP):
        packet_1_proto = "IP"
    if (request_packets[0]).haslayer(TCP):
        packet_1_proto = "TCP"
        packet_1_port = request_packets[0][TCP].dport
    elif (request_packets[0]).haslayer(UDP):
        packet_1_proto = "UDP"
        packet_1_port = request_packets[0][UDP].dport
    elif(request_packets[0]).haslayer(ICMP):
        packet_1_proto = "ICMP"
    if have_2_packet:
        if (request_packets[1]).haslayer(IP):
            packet_2_proto = "IP"
        if (request_packets[1]).haslayer(TCP):
            packet_2_proto = "TCP"
            packet_2_port = request_packets[1][TCP].dport
        elif (request_packets[1]).haslayer(UDP):
            packet_2_proto = "UDP"
            packet_2_port = request_packets[1][UDP].dport
        elif(request_packets[1]).haslayer(ICMP):
            packet_2_proto = "ICMP"
    return packet_1_proto, packet_2_proto, packet_1_port, packet_2_port


def save_measurement_data(
        request_ips, measurement_name, continue_to_max_ttl, output_dir):
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
    data_path = output_dir + measurement_name + ".json"
    with open(data_path, "a") as jsonfile:
        jsonfile.write(json.dumps(measurement_data_json,
                       default=lambda o: o.__dict__, indent=4))
    print("saved: " + data_path)
    return data_path


def check_for_permission():
    try:
        this_request = IP(
            dst=LOCALHOST, ttl=0)/TCP(
            sport=0, dport=53)/DNS()
        sr1(this_request, verbose=0, timeout=0)
    except OSError:
        print("Error: Unable to send a packet with unprivileged user. Please run as root/admin.")
        sys.exit(1)


def trace_route(
        ip_list, request_packet_1, output_dir: str,
        max_ttl: int, timeout: int,
        request_packet_2: str = "", name_prefix: str = "",
        annotation_1: str = "", annotation_2: str = "",
        continue_to_max_ttl: bool = False,
        do_tcph1: bool = False, do_tcph2: bool = False,
        trace_retransmission: bool = False
):
    check_for_permission()
    measurement_name = ""
    request_packets = []
    do_tcphandshake = []
    request_ips = []
    was_successful = False
    global have_2_packet
    if do_tcph1:
        annotation_1 += " (+tcph)"
    if do_tcph2:
        annotation_2 += " (+tcph)"
    if request_packet_1 is None:
        print("packet is invalid!")
        exit()
    if request_packet_2 == "":
        if trace_retransmission:
            request_packet_1[IP].id += 15  # == sysctl net.ipv4.tcp_retries2
        request_packets.append(request_packet_1)
        do_tcphandshake.append(do_tcph1)
        have_2_packet = False
    else:
        if trace_retransmission:
            request_packet_1[IP].id += 15  # == sysctl net.ipv4.tcp_retries2
            request_packet_2[IP].id += 15  # == sysctl net.ipv4.tcp_retries2
        request_packets.append(request_packet_1)
        request_packets.append(request_packet_2)
        do_tcphandshake.append(do_tcph1)
        do_tcphandshake.append(do_tcph2)
        have_2_packet = True
    if len(ip_list) == 0:
        if request_packet_1[IP].dst == "" or request_packet_1[IP].dst == LOCALHOST:
            if have_2_packet:
                if request_packet_2[IP].dst == "" or request_packet_2[IP].dst == LOCALHOST:
                    print("You must set at least one IP. (--ips || -i)")
                    exit()
            else:
                print("You must set at least one IP. (--ips || -i)")
                exit()
        else:
            request_ips.append(request_packet_1[IP].dst)
        if have_2_packet:
            if request_packet_2[IP].dst != "" or request_packet_2[IP].dst != LOCALHOST:
                request_ips.append(request_packet_2[IP].dst)
    else:
        request_ips = ip_list
    if name_prefix != "":
        measurement_name = name_prefix + "-tracevis-" + \
            datetime.utcnow().strftime("%Y%m%d-%H%M")
    else:
        measurement_name = "tracevis-" + datetime.utcnow().strftime("%Y%m%d-%H%M")
    repeat_all_steps = 0
    packet_1_proto, packet_2_proto, packet_1_port, packet_2_port = get_packets_info(
        request_packets)
    initialize_json_first_nodes(
        request_ips=request_ips, annotation_1=annotation_1, annotation_2=annotation_2,
        packet_1_proto=packet_1_proto, packet_2_proto=packet_2_proto,
        packet_1_port=packet_1_port, packet_2_port=packet_2_port
    )
    print("- · - · -     - · - · -     - · - · -     - · - · -")
    while repeat_all_steps < 3:
        repeat_all_steps += 1
        previous_node_ids = initialize_first_nodes(request_ips)
        for current_ttl in range(1, max_ttl + 1):
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
                print(
                    "  · - · - · repeat step: " + str(repeat_all_steps)
                    + "  · - · - ·  ttl step: " + str(current_ttl) + " · - · - ·")
                print(" · · · - - - · · ·     · · · - - - · · ·     · · · - - - · · · ")
                while ip_steps < len(request_ips):
                    sleep_time = SLEEP_TIME
                    not_yet_destination = not (already_reached_destination(
                        previous_node_ids[access_block_steps][ip_steps],
                        request_ips[ip_steps]))
                    if not continue_to_max_ttl:
                        if not_yet_destination:
                            answer_ip, elapsed_ms, packet_size, req_answer_ttl, answer_summary = send_packet(
                                request_packets[access_block_steps], request_ips[ip_steps],
                                current_ttl, timeout, do_tcphandshake[access_block_steps], trace_retransmission)
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
                            current_ttl, timeout, do_tcphandshake[access_block_steps], trace_retransmission)
                        measurement_data[access_block_steps][ip_steps].add_hop(
                            current_ttl, answer_ip, elapsed_ms, packet_size, req_answer_ttl, answer_summary
                        )
                    if not_yet_destination:
                        if answer_ip == "***":
                            sleep_time = 0
                        previous_node_ids[access_block_steps][ip_steps] = answer_ip
                    print(
                        " · · · - - - · · ·     · · · - - - · · ·     · · · - - - · · · ")
                    sleep(sleep_time)
                    ip_steps += 1
                    was_successful = True
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
    if was_successful:
        print("saving measurement data...")
        data_path = save_measurement_data(
            request_ips, measurement_name, continue_to_max_ttl, output_dir)
        print("· · · - · -     · · · - · -     · · · - · -     · · · - · -")
        return(was_successful, data_path)
    else:
        return(was_successful, "")
