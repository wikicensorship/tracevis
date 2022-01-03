#!/usr/bin/env python3
import json


class traceroute_data:
    def __init__(
        self, dst_addr: str, annotation: str, proto: str, timestamp: int,
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
        self.result = []
        self.size = size
        self.src_addr = src_addr
        self.timestamp = timestamp
        self.ttr = ttr

    def add_hop(self, hop, from_ip, rtt, size, ttl, answer_summary):
        if len(self.result) < hop:
            (self.result).append({"hop": hop, "result": []})
        if rtt == 0:
            self.result[hop - 1]["result"].append({
                "x": "-",
            })
        elif from_ip == "***":
            self.result[hop - 1]["result"].append({
                "x": "*",
            })
        else:
            self.result[hop - 1]["result"].append({
                "from": from_ip,
                "rtt": rtt,
                "size": size,
                "ttl": ttl,
                "summary": answer_summary
            })

    def set_endtime(self, endtime):
        self.endtime = endtime

    def clean_extra_result(self):
        result_index = 0
        for try_step in self.result:  # will be up to 255
            results = try_step["result"]
            repeat_steps = 0
            for result in results:  # will be up to 3
                if "x" in result.keys():
                    if '-' == result["x"]:
                        repeat_steps += 1
            if repeat_steps == 3:
                del self.result[result_index:]
                break
            result_index += 1

    def json(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          indent=4)
