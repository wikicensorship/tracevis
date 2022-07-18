#!/usr/bin/env python3

import os
import json
import time
import platform
from urllib.request import Request, urlopen
from threading import Thread 



OS_NAME = platform.system()


def get_meta_json():
    meta_url = 'https://speed.cloudflare.com/meta'
    # TODO(xhdix): change versioning
    httprequest = Request(
        meta_url, headers={'user-agent': 'TraceVis/0.7.0 (WikiCensorship)'})
    try:
        with urlopen(httprequest, timeout=9) as response:
            if response.status == 200:
                meta_json = json.load(response)
                return meta_json
            else:
                return None
    except Exception as e:
        print(f"Notice!\n{e!s}")
        return None


def drop_privileges():
    if os.name == 'posix':
        if os.geteuid() == 0:
            uid = os.geteuid()
            gid = os.getegid()
            os.setegid(65534)
            os.seteuid(65534)
            return uid, gid
    return None, None

def gain_privileges(uid, gid):
    if uid is not None and gid is not None:
        os.setegid(gid)
        os.seteuid(uid)


def run_geolocate():
    def get_meta():
        nonlocal no_internet, public_ip, network_asn, network_name, country_code, city, is_canceled, is_done

        no_internet = True
        public_ip = '127.1.2.7'  # we should know that what we are going to clean
        network_asn = 'AS0'
        network_name = ''
        country_code = ''
        city = ''


        print("· - · · · detecting IP, ASN, country, etc · - · · · ")
        user_meta = get_meta_json()
        if is_canceled:
            return
        if user_meta is not None :
            no_internet = False
            if 'clientIp' in user_meta.keys():
                public_ip = user_meta['clientIp']
                print("· · · - · " + public_ip)
                print('. - . - . we use public IP to know what to remove from data!')
            if 'asn' in user_meta.keys():
                network_asn = ("AS" + str(user_meta['asn']))
                print("· · · - · " + network_asn)
            if 'asOrganization' in user_meta.keys():
                network_name = user_meta['asOrganization']
                print("· · · - · " + network_name)
            if 'country' in user_meta.keys():
                country_code = user_meta['country']
                print("· · · - · " + country_code)
            if 'city' in user_meta.keys():
                city = user_meta['city']
                print("· · · - · " + city)
        is_done = True


    user_meta_info_timeout = 10   # Seconds
    no_internet = True 
    public_ip = ""
    network_asn = ""
    network_name = ""
    country_code = ""
    city = ""
    is_done = False
    is_canceled = False

    user_meta_info_start_time = 0

    uid, gid = drop_privileges()
    p = Thread(target=get_meta, daemon=True)
    p.start()
    user_meta_info_start_time = time.time()
    while time.time() - user_meta_info_start_time < user_meta_info_timeout and not is_done:
        time.sleep(1)
    if not is_done:
        is_canceled = True
        
    gain_privileges(uid, gid)
    return no_internet, public_ip, network_asn, network_name, country_code, city

