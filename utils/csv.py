#!/usr/bin/env python3
import json
import os.path

def parse_json(file_name:str) -> list:
    data = []
    with open(file_name, "r") as f:
        json_str = f.read()
    try:
        json_data = json.loads(json_str)
    except:
        print("JSON format is not valid!")
        return ""
    for measurement in json_data:
        dst_addr = measurement["dst_addr"]
        proto = measurement["proto"]
        annot = measurement["annotation"]
        for hop_row in measurement["result"]:
            hop = hop_row["hop"]
            res_from = []
            rtt = []
            ttl = []
            for i in range(3):
                try:
                    res_from.append(hop_row["result"][i]["from"])
                    rtt.append(hop_row["result"][i]["rtt"])
                    ttl.append(hop_row["result"][i]["ttl"])
                except:
                    res_from.append("*")
                    rtt.append("*")
                    ttl.append("*")
            data.append({
                "dst_addr": dst_addr,
                "proto": proto,
                "annot": annot,
                "hop": hop,
                "res_from1": res_from[0],
                "rtt1": rtt[0],
                "ttl1": ttl[0],
                "res_from2": res_from[1],
                "rtt2": rtt[1],
                "ttl2": ttl[1],
                "res_from3": res_from[2],
                "rtt3": rtt[2],
                "ttl3": ttl[2]
            })
    return data

def json2csv_raw(file_name:str) -> str:
    csv_str = 'dst_addr,proto,annot,hop,res_from1,rtt1,ttl1,res_from2,rtt2,ttl2,res_from3,rtt3,ttl3\n'
    data = parse_json(file_name)
    for row in data:
        csv_str += "{},{},{},{},{},{},{},{},{},{},{},{},{}\n".format(
            row["dst_addr"], row["proto"], row["annot"], row["hop"],
            row["res_from1"], row["rtt1"], row["ttl1"],
            row["res_from2"], row["rtt2"], row["ttl2"],
            row["res_from3"], row["rtt3"], row["ttl3"]
        )
    return csv_str

def json2csv_clean(file_name:str) -> str:
    csv_str = 'dst_addr,proto,annot,hop,res_from1,rtt1,ttl1,res_from2,rtt2,ttl2,res_from3,rtt3,ttl3\n'
    data = parse_json(file_name)
    data = sorted(data, key=lambda d: d['hop'])
    last_hop = 1
    for row in data:
        if row["hop"] > last_hop:
            csv_str += ",,,,,,,,,,,,\n"
        csv_str += "{},{},{},{},{},{},{},{},{},{},{},{},{}\n".format(
            row["dst_addr"], row["proto"], row["annot"], row["hop"],
            row["res_from1"], row["rtt1"], row["ttl1"],
            row["res_from2"], row["rtt2"], row["ttl2"],
            row["res_from3"], row["rtt3"], row["ttl3"]
        )
        last_hop = row["hop"]
    return csv_str

def json2csv(file_name:str):
    if os.path.isfile(file_name):
        with open(file_name.replace(".json", ".csv"), "w") as f:
            csv = json2csv_clean(file_name)
            if csv != "":
                f.write(csv)
    else:
        print("File does not exist!")