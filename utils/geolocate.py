#!/usr/bin/env python3

import json
import os
import platform
from urllib.request import Request, urlopen

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, RandShort, sr

import utils.ephemeral_port

OS_NAME = platform.system()


def nslookup(user_iface, user_source_ip_address):
    # there is no timeout in getaddrinfo(), so we have to do it ourselves
    # Raw packets bypasses the firewall so it may not work as intended in some cases
    dns_request = IP(src=user_source_ip_address,
        dst="1.1.1.1", id=RandShort(), ttl=128)/UDP(
        sport=utils.ephemeral_port.ephemeral_port_reserve(user_source_ip_address,"udp"), dport=53)/DNS(
            rd=1, id=RandShort(), qd=DNSQR(qname="speed.cloudflare.com"))
    try:
        request_and_answers, _ = sr(
            dns_request, iface=user_iface, verbose=0, timeout=1)
    except:
        return False
    if request_and_answers is not None and len(request_and_answers) != 0:
        if request_and_answers[0][1].haslayer(DNS):
            return True
            # return request_and_answers[0][1][DNSRR].rdata
    return False


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


def get_meta(user_iface, user_source_ip_address):
    no_internet = True
    public_ip = '127.1.2.7'  # we should know that what we are going to clean
    network_asn = 'AS0'
    network_name = ''
    country_code = ''
    city = ''
    print("· - · · · detecting IP, ASN, country, etc · - · · · ")
    if not nslookup(user_iface, user_source_ip_address):
        return no_internet, public_ip, network_asn, network_name, country_code, city
    user_meta = get_meta_json()
    if user_meta is not None:
        no_internet = False
        if 'clientIp' in user_meta.keys():
            public_ip = user_meta['clientIp']
            print("· · · - · " + public_ip)
            print('. - . - . we use public IP to know what to remove from data!')
        if 'asn' in user_meta.keys():
            network_asn = "AS" + str(user_meta['asn'])
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
    return no_internet, public_ip, network_asn, network_name, country_code, city
