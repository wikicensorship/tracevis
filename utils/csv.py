#!/usr/bin/env python3
import json
import os.path


def parse_json(file_name: str) -> list:
    data = []
    with open(file_name, "r") as jsonfile:
        json_str = jsonfile.read()
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
            skip_next = False
            for result in hop_row["result"]:
                if skip_next:
                    skip_next = False
                    continue
                if "late" in result.keys():
                    skip_next = True
                if 'x' in result.keys():
                    res_from.append(result["x"])
                    rtt.append(result["x"])
                    ttl.append(result["x"])
                else:
                    res_from.append(result["from"])
                    if "rtt" in result.keys():
                        rtt.append(result["rtt"])
                    else:
                        rtt.append("*")
                    ttl.append(result["ttl"])
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


def json2csv_raw(file_name: str) -> str:
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


def json2csv_clean(file_name: str) -> str:
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


def json2csv(file_name: str):
    if os.path.isfile(file_name):
        with open(file_name.replace(".json", ".csv"), "w") as csvfile:
            csv = json2csv_clean(file_name)
            if csv != "":
                print("saving measurement graph...")
                csvfile.write(csv)
                print("saved: " + file_name)
    else:
        print("error: " + file_name + " does not exist!")
