#!/usr/bin/env python3

from base64 import b64encode


# this function source: https://stackoverflow.com/a/64410921
def packet2json(packet_obj, public_ip):
    packet_dict = {}
    layer = ''
    for line in packet_obj.show2(dump=True).split('\n'):
        if '###' in line:
            layer = line.strip('#[] ')
            packet_dict[layer] = {}
        elif '=' in line:
            key, val = line.split('=', 1)
            val = val.replace(public_ip, '127.1.2.7')
            if layer in ['Raw','payload'] and key.strip() == 'load':
                packet_dict[layer][key.strip()] = b64encode(
                    packet_obj[layer].load).decode()
            else:
                packet_dict[layer][key.strip()] = val.strip()
    return packet_dict


def packetlist2json(answered, unanswered, public_ip):
    packetlist = {'sent': [], 'received': []}
    if len(answered) == 0:
        if len(unanswered) != 0:
            packetlist["sent"] = packet2json(packet_obj=unanswered[0],
                                             public_ip=public_ip)
    else:
        for sentp, receivedp in answered:
            if len(packetlist["sent"]) == 0:
                packetlist["sent"] = packet2json(packet_obj=sentp,
                                                 public_ip=public_ip)
            packetlist["received"].append(
                packet2json(packet_obj=receivedp, public_ip=public_ip))
    return packetlist
