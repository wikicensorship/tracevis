#!/usr/bin/env python3

from base64 import b64encode


# this function source: https://stackoverflow.com/a/64410921
def packet2json(packet_obj):
    packet_dict = {}
    layer = ''
    for line in packet_obj.show2(dump=True).split('\n'):
        if '###' in line:
            layer = line.strip('#[] ')
            packet_dict[layer] = {}
        elif '=' in line:
            key, val = line.split('=', 1)
            if layer == 'Raw' and key.strip() == 'load':
                packet_dict[layer][key.strip()] = b64encode(packet_obj['Raw'].load).decode()
            else:
                packet_dict[layer][key.strip()] = val.strip()
    return packet_dict

def packetlist2json(answered, unanswered):
    packetlist = {'sent': [], 'received': []}
    if len(answered) == 0:
        if len(unanswered) != 0:
            packetlist["sent"] = packet2json(packet_obj=unanswered[0])
    else:
        for sentp, receivedp in answered:
            if len(packetlist["sent"]) == 0:
                packetlist["sent"] = packet2json(packet_obj=sentp)
            packetlist["received"].append(
                packet2json(packet_obj=receivedp))
    return packetlist
