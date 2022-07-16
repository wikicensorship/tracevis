#!/usr/bin/env python3

import os
import json
import time
import ctypes 
import platform
import utils.ephemeral_port 
from urllib.request import Request, urlopen
from multiprocessing import Process, Value, RawArray 
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, RandShort, sr




OS_NAME = platform.system()

def drop_privileges():
    if os.name == 'posix':
        if os.getuid() == 0:
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
            os.umask(0o077)


def get_meta_json():
    usereuid = None
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
    finally:
        if usereuid != None:
            os.seteuid(usereuid)


def run_geolocate(user_iface):
    USER_META_INFO_TIMEOUT = 60   # Seconds
    USER_META_INFO_NO_INTERNET = Value(ctypes.c_bool, True)
    USER_META_INFO_PUBLIC_IP = RawArray(ctypes.c_wchar, 40)
    USER_META_INFO_NETWORK_ASN = RawArray(ctypes.c_wchar, 100)
    USER_META_INFO_NETWORK_NAME = RawArray(ctypes.c_wchar, 100)
    USER_META_INFO_COUNTRY_CODE = RawArray(ctypes.c_wchar, 100)
    USER_META_INFO_CITY = RawArray(ctypes.c_wchar, 100)
    USER_META_INFO_START_TIME = 0
    USER_META_INFO_DONE = Value(ctypes.c_bool, False)

    p = Process(target=get_meta, 
                args=(USER_META_INFO_NO_INTERNET, USER_META_INFO_PUBLIC_IP, 
                      USER_META_INFO_NETWORK_ASN, USER_META_INFO_NETWORK_NAME, 
                      USER_META_INFO_COUNTRY_CODE, USER_META_INFO_CITY, USER_META_INFO_DONE, user_iface), 
                daemon=True)
    p.start()
    USER_META_INFO_START_TIME = time.time()
    while time.time() - USER_META_INFO_START_TIME < USER_META_INFO_TIMEOUT and not USER_META_INFO_DONE.value:
        time.sleep(1)

    network_asn = USER_META_INFO_NETWORK_ASN.value
    network_name = USER_META_INFO_NETWORK_NAME.value
    country_code = USER_META_INFO_COUNTRY_CODE.value
    city = USER_META_INFO_CITY.value
    public_ip = USER_META_INFO_PUBLIC_IP.value
    no_internet = USER_META_INFO_NO_INTERNET.value

    return no_internet, public_ip, network_asn, network_name, country_code, city

def get_meta(no_internet, public_ip, network_asn, network_name, country_code, city, is_done, user_iface=None):
    no_internet.value = True
    public_ip.value = '127.1.2.7'  # we should know that what we are going to clean
    network_asn.value = 'AS0'
    network_name.value = ''
    country_code.value = ''
    city.value = ''

    drop_privileges()

    result_message =  "+=======================================================================+\n"
    result_message += "|         · - · · · detecting IP, ASN, country, etc · - · · ·           |\n"
    user_meta = get_meta_json()
    if user_meta is not None:
        no_internet.value = False
        if 'clientIp' in user_meta.keys():
            public_ip.value = user_meta['clientIp']
            result_message += "|" + public_ip.value.center(71) + "|\n"
            result_message += '|' + 'we use public IP to know what to remove from data!'.center(71) + '|\n'
        if 'asn' in user_meta.keys():
            network_asn.value = ("AS" + str(user_meta['asn']))
            result_message += "|" + network_asn.value.center(71) + '|\n'
        if 'asOrganization' in user_meta.keys():
            network_name.value = user_meta['asOrganization']
            result_message += "|" + network_name.value.center(71) + '|\n'
        if 'country' in user_meta.keys():
            country_code.value = user_meta['country']
            result_message += "|" + country_code.value.center(71) + '|\n'
        if 'city' in user_meta.keys():
            city.value = user_meta['city']
            result_message += "|" + city.value.center(71) + '|\n'
    result_message += '+=======================================================================+\n'
    print(result_message)
    is_done.value = True
