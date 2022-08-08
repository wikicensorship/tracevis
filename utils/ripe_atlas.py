#!/usr/bin/env python3

import json
import sys
import urllib.request
from datetime import datetime
from time import sleep

MEASUREMENT_IDS = [
    5011,  # c.root-servers.net
    5013,  # e.root-servers.net
    5004,  # f.root-servers.net
    5005,  # i.root-servers.net
    5001,  # k.root-servers.net
    5008,  # l.root-servers.net
    5006,  # m.root-servers.net
    5005,  # topology4.dyndns.atlas.ripe.net
    5151  # topology4.dyndns.atlas.ripe.net
]


def download_from_atlas(
        probe_id, output_dir: str, name_prefix: str = "",
        measurement_ids: str = ""):
    all_measurements = []
    measurement_name = ""
    was_successful = False
    if measurement_ids == "":
        measurement_ids = MEASUREMENT_IDS
    if name_prefix != "":
        measurement_name = name_prefix + "-ripe-atlas-" + str(probe_id) + "-tracevis-" \
            + datetime.utcnow().strftime("%Y%m%d-%H%M")
    else:
        measurement_name = "ripe-atlas-" + str(probe_id) + "-tracevis-" \
            + datetime.utcnow().strftime("%Y%m%d-%H%M")
    if probe_id != "":
        print(
            " ********************************************************************** ")
        print(
            "downloading data from probe ID: " + str(probe_id))
        print(" · · · - - - · · ·     · · · - - - · · ·     · · · - - - · · · ")
        for measurement_id in measurement_ids:
            print(
                "downloading measurement ID: " + str(measurement_id))
            requset_url = ("https://atlas.ripe.net/api/v2/measurements/"
                           + str(measurement_id)
                           + "/latest/?format=json&probe_ids="
                           + str(probe_id)
                           )
            with urllib.request.urlopen(requset_url) as url:
                downloaded_data = json.loads(url.read().decode())
            if downloaded_data is not None:
                all_measurements.append(downloaded_data[0])
                print(
                    "downloading measurement ID " + str(measurement_id) + " finished.")
            else:
                print("failed to download measurement ID: "
                      + str(measurement_id))
            sleep(3)
            print(" · · · - - - · · ·     · · · - - - · · ·     · · · - - - · · · ")
        print(
            " ********************************************************************** ")
        if len(all_measurements) < 1:
            sys.exit(1)
        measurement_path = output_dir + measurement_name + ".json"
        print("saving json file... to: " + measurement_path)
        with open((measurement_path), 'w', encoding='utf-8') as json_file:
            json.dump(all_measurements, json_file,
                      ensure_ascii=False, indent=4)
        print("saved: " + measurement_path)
        was_successful = True
        print(
            " ********************************************************************** ")
        return was_successful, measurement_path
