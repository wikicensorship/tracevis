import json

class Traceroute:
    def __init__(
        self, dst_addr: str, dst_name: str,
        from_ip: str, msm_id: int,
        msm_name: str, prb_id: int, proto: str,
        src_addr: str, timestamp: int, ttr: float = -1,
        type: str = "traceroute", af: int = 4, lts: int = -1, paris_id: int = -1, size: int = -1
    ) -> None:
        self.af = af
        self.dst_addr = dst_addr
        self.dst_name = dst_name
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
        self.type = type

    def add_hop(self, hop, from_ip, rtt, size, ttl):
        if len(self.result) < hop:
            (self.result).append({"hop": hop, "result": []})
        if from_ip == "***":
            self.result[hop - 1]["result"].append({
                "x": "*",
            })
        else:
            self.result[hop - 1]["result"].append({
                "from": from_ip,
                "rtt": rtt,
                "size": size,
                "ttl": ttl
            })

    def json(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
            indent=4)