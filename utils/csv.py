#!/usr/bin/env python3
import json
import os.path

csv_header_all = ""
csv_blank_row = ""
csv_prepared_row = ""


def prepare_csv_variables(keys):
    global csv_header_all
    global csv_blank_row
    global csv_prepared_row
    for item in keys:
        csv_header_all += item + ','
        csv_blank_row += ','
        csv_prepared_row += "{" + item + "},"
    csv_header_all += '\r\n'
    csv_blank_row += '\r\n'
    csv_prepared_row += '\r\n'


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
        if "annotation" in measurement.keys():
            annot = measurement["annotation"]
        else:
            annot = "-"
        for hop_row in measurement["result"]:
            hop = hop_row["hop"]
            res_from = []
            rtt = []
            ttl = []
            summary = []
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
                    summary.append("-")
                else:
                    res_from.append(result["from"])
                    if "rtt" in result.keys():
                        rtt.append(result["rtt"])
                    else:
                        rtt.append("*")
                    ttl.append(result["ttl"])
                    if "summary" in result.keys():
                        summary.append(result["summary"])
                    else:
                        summary.append("-")
            data.append({
                "destination_address": dst_addr,
                "protocol": proto,
                "annotation": annot,
                "hop": hop,
                "response_from_1": res_from[0],
                "rtt_1": rtt[0],
                "ttl_1": ttl[0],
                "response_from_2": res_from[1],
                "rtt_2": rtt[1],
                "ttl_2": ttl[1],
                "response_from_3": res_from[2],
                "rtt_3": rtt[2],
                "ttl_3": ttl[2],
                "summary_1": summary[0],
                "summary_2": summary[1],
                "summary_3": summary[2],
            })
    return data


def json2csv_raw(data: list) -> str:
    global csv_header_all
    global csv_blank_row
    global csv_prepared_row
    csv_str = csv_header_all
    last_hop = 1
    for row in data:
        if row["hop"] < last_hop:
            csv_str += csv_blank_row
        csv_str += csv_prepared_row.format_map(row)
        last_hop = row["hop"]
    return csv_str


def json2csv_clean(data: list) -> str:
    global csv_header_all
    global csv_blank_row
    global csv_prepared_row
    csv_str = csv_header_all
    data = sorted(data, key=lambda d: d['hop'])
    last_hop = 1
    for row in data:
        if row["hop"] > last_hop:
            csv_str += csv_blank_row
        csv_str += csv_prepared_row.format_map(row)
        last_hop = row["hop"]
    return csv_str


def json2csv(file_name: str, sorted: bool = True):
    if os.path.isfile(file_name):
        new_file_name = file_name.replace(".json", ".csv")
        data = parse_json(file_name)
        prepare_csv_variables(data[0].keys())
        with open(new_file_name, "w") as csvfile:
            csv = ""
            if sorted:
                csv = json2csv_clean(data)
            else:
                csv = json2csv_raw(data)
            if csv != "":
                print("saving measurement in csv...")
                csvfile.write(csv)
                print("saved: " + new_file_name)
    else:
        print("error: " + file_name + " does not exist!")
