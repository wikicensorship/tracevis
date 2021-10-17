#!/usr/bin/env python3
from scapy.all import *
from pyvis.network import Network
import networkx as nx
from time import sleep
import ipaddress
sleeptime = 1
previous_ip_id = [[1,1,1],[1,1,1]]
device_color = "Chocolate"
router_color = "green"
windows_color = "blue"
linux_color = "purple"
request_access_color = ["DarkTurquoise", "MediumSpringGreen", "DodgerBlue"]
request_block_color = ["HotPink", "Red", "Orange"]
request_color = request_access_color
none_color = "gray"
request_ip = ["8.8.4.4", "1.0.0.1", "9.9.9.9"]
accessible_addr = "www.google.com"
blocked_addr = "www.twitter.com"
request_addr = accessible_addr
multi_graph = nx.MultiGraph()
multi_graph.add_node(1, label = "this device", color = device_color)
for current_ttl in range(0,30):
    request_addr = accessible_addr
    request_color = request_access_color
    i = 0
    ii = 0
    print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
    while i < 3:
        dns_request = IP(dst=request_ip[i], id=RandShort(), ttl=current_ttl)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, id=RandShort(), qd=DNSQR(qname=request_addr))
        print(">>>request:" + "   ip.dst: " + dns_request[IP].dst + "   ip.ttl: " + str(current_ttl))
        req_answer = sr1(dns_request, verbose=0, timeout=3)
        if req_answer is not None:
            backttl = 0
            if req_answer[IP].ttl <= 64 :
                backttl = 64 - req_answer[IP].ttl
                device_color = linux_color
            elif req_answer[IP].ttl <= 128 :
                backttl = 128 - req_answer[IP].ttl
                device_color = windows_color
            else :
                backttl = 255 - req_answer[IP].ttl
                device_color = router_color
            print("   <<< answer:" + "   ip.src: " + req_answer[IP].src + "   ip.ttl: " + str(req_answer[IP].ttl) + "   back-ttl: " + str(backttl))
            print("      " + req_answer.summary())
            if int(ipaddress.IPv4Address(request_ip[i])) != previous_ip_id[ii][i] :
                current_ip_id = int(ipaddress.IPv4Address(req_answer[IP].src))
                if not multi_graph.has_node(current_ip_id) :
                    multi_graph.add_node(current_ip_id, label = req_answer[IP].src, color = device_color, title = str(current_ttl))
                multi_graph.add_edge(previous_ip_id[ii][i], current_ip_id, color = request_color[i], title = str(backttl))
                previous_ip_id[ii][i] = current_ip_id
        else:
            print(" *** no response *** ")
            if int(ipaddress.IPv4Address(request_ip[i])) != previous_ip_id[ii][i] :
                if not multi_graph.has_node(1000 + current_ttl) :
                    multi_graph.add_node(1000 + current_ttl, label = "***", color = none_color, title = str(current_ttl))
                multi_graph.add_edge(previous_ip_id[ii][i], 1000 + current_ttl, color = request_color[i], title = "***" + str(current_ttl))
                previous_ip_id[ii][i] = 1000 + current_ttl
        print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
        sleep(sleeptime)
        i += 1
        if i == 3 and request_addr == accessible_addr :
            request_addr = blocked_addr
            request_color = request_block_color
            i = 0
            ii = 1
            print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
            print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
        net_vis = Network(directed=True)
        net_vis.from_nx(multi_graph)
        net_vis.set_edge_smooth('dynamic')
        net_vis.show("nods.html")
    print(" ********************************************************************** ")
    print(" ********************************************************************** ")
    print(" ********************************************************************** ")
net_vis = Network(directed=True)
net_vis.from_nx(multi_graph)
net_vis.set_edge_smooth('dynamic')
net_vis.show("nods.html")