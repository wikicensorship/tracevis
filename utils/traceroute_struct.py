#!/usr/bin/env python3
import json


class traceroute_data:
    def __init__(
        self, dst_addr: str, annotation: str, proto: str, port: int, timestamp: int,
        src_addr: str = "127.0.0.2", from_ip: str = "127.0.0.1",
        prb_id: int = -1, msm_id: int = -1, msm_name: str = "traceroute",
        ttr: float = -1, af: int = 4, lts: int = -1, paris_id: int = -1,
        size: int = -1, dst_name: str = ""
    ) -> None:
        self.af = af
        self.dst_addr = dst_addr
        self.dst_name = dst_name
        self.annotation = annotation
        self.endtime = -1
        self.from_ip = from_ip
        self.lts = lts
        self.msm_id = msm_id
        self.msm_name = msm_name
        self.paris_id = paris_id
        self.prb_id = prb_id
        self.proto = proto
        self.port = port
        self.result = []
        self.size = size
        self.src_addr = src_addr
        self.timestamp = timestamp
        self.ttr = ttr

    def add_hop(self, hop, from_ip, rtt, size, ttl, answer_summary, answered, unanswered):
        if len(self.result) < hop:
            (self.result).append({"hop": hop, "result": []})
        if rtt == 0:
            self.result[hop - 1]["result"].append({
                "x": "-",
            })
        elif from_ip == "***":
            packetlist = self.packetlist2json(answered, unanswered)
            self.result[hop - 1]["result"].append({
                "x": "*",
                "packets": packetlist,
            })
        else:
            packetlist = self.packetlist2json(answered, unanswered)
            self.result[hop - 1]["result"].append({
                "from": from_ip,
                "rtt": rtt,
                "size": size,
                "ttl": ttl,
                "summary": answer_summary,
                "packets": packetlist,
            })

    def set_endtime(self, endtime):
        self.endtime = endtime

    # this function source: https://stackoverflow.com/a/64410921
    def packet2json(self, packet):
        packet_dict = {}
        for line in packet.show2(dump=True).split('\n'):
            if '###' in line:
                layer = line.strip('#[] ')
                packet_dict[layer] = {}
            elif '=' in line:
                key, val = line.split('=', 1)
                packet_dict[layer][key.strip()] = val.strip()
        return packet_dict

    def packetlist2json(self, answered, unanswered):
        packetlist = {'sent': [], 'received': []}
        if len(answered) == 0:
            if len(unanswered) != 0:
                packetlist["sent"] = self.packet2json(packet=unanswered[0])
        else:
            for sentp, receivedp in answered:
                if len(packetlist["sent"]) == 0:
                    packetlist["sent"] = self.packet2json(packet=sentp)
                packetlist["received"].append(
                    self.packet2json(packet=receivedp))
        return packetlist

    def clean_extra_result(self):
        result_index = 0
        for try_step in self.result:  # will be up to 255
            results = try_step["result"]
            repeat_steps = 0
            for result in results:  # will be unknown
                if "x" in result.keys():
                    if '-' == result["x"]:
                        repeat_steps += 1
            if repeat_steps == len(results):
                del self.result[result_index:]
                break
            result_index += 1

    def json(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          indent=4)
