#!/usr/bin/env python3
import json
import os.path
import logging 
logger = logging.getLogger(__name__)

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
    csv_header_all += '\n'
    csv_blank_row += '\n'
    csv_prepared_row += '\n'


def parse_json(file_name: str) -> list:
    data = []
    with open(file_name, "r") as jsonfile:
        json_str = jsonfile.read()
    try:
        json_data = json.loads(json_str)
    except:
        logger.error("JSON format is not valid!")
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


def data_to_csv(data: list, sort_it: bool) -> str:
    global csv_header_all
    global csv_blank_row
    global csv_prepared_row
    csv_str = csv_header_all
    last_hop = 1
    for row in data:
        if sort_it:
            if row["hop"] > last_hop:
                csv_str += csv_blank_row
        else:
            if row["hop"] < last_hop:
                csv_str += csv_blank_row
        csv_str += csv_prepared_row.format_map(row)
        last_hop = row["hop"]
    return csv_str


def json2csv(file_name: str, sort_it: bool = True):
    if os.path.isfile(file_name):
        new_file_name = file_name.replace(".json", ".csv")
        data = parse_json(file_name)
        prepare_csv_variables(data[0].keys())
        with open(new_file_name, "w") as csvfile:
            if sort_it:
                data = sorted(data, key=lambda d: d['hop'])
            csv = data_to_csv(data, sort_it)
            if csv != "": # todo (xhdix): it will never be empty. we shold do better
                logger.info("saving measurement in csv...")
                csvfile.write(csv)
                logger.info("saved: " + new_file_name)
    else:
        logger.error("error: " + file_name + " does not exist!")
