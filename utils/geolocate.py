#!/usr/bin/env python3

import json
import os
import platform
from urllib.request import Request, urlopen

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, RandShort, sr

import utils.ephemeral_port 
import pwd, grp



OS_NAME = platform.system()

def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    if os.getuid() == 0:
        running_uid = pwd.getpwnam(uid_name).pw_uid
        running_gid = grp.getgrnam(gid_name).gr_gid

        os.setgroups([])
        os.setgid(running_gid)
        os.setuid(running_uid)
        os.umask(0o077)


def get_meta_json():
    usereuid = None
    meta_url = 'https://speed.cloudflare.com/meta'
    # TODO(xhdix): change versioning
    httprequest = Request(
        meta_url, headers={'user-agent': 'TraceVis/0.7.0 (WikiCensorship)'})
    try:
        if OS_NAME == "Linux":
            if os.geteuid() == 0:
                usereuid = os.geteuid()
                os.seteuid(65534)  # user id of the user "nobody"
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
