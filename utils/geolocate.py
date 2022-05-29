#!/usr/bin/env python3

import os

import requests
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr
from scapy.volatile import RandShort

import utils.ephemeral_port


# there is no timeout in getaddrinfo(), so we have to do it ourselves
def nslookup():
    dns_request = IP(
        dst="1.1.1.1", id=RandShort(), ttl=128)/UDP(
        sport=utils.ephemeral_port.ephemeral_port_reserve("udp"), dport=53)/DNS(
            rd=1, id=RandShort(), qd=DNSQR(qname="speed.cloudflare.com"))
    try:
        request_and_answers, _ = sr(
            dns_request, verbose=0, timeout=1)
    except:
        return False
    if request_and_answers is not None and len(request_and_answers) != 0:
        if request_and_answers[0][1].haslayer(DNS):
            return True
            # return request_and_answers[0][1][DNSRR].rdata
    return False


def get_meta():
    no_interent = False
    public_ip = '127.1.2.7'  # we should know that what we are going to clean
    network_asn = 'AS0'
    network_name = ''
    country_code = ''
    usereuid = None
    try:
        print("· - · · · detecting IP, ASN, country, etc · - · · · ")
        if not nslookup():
            return no_interent, public_ip, network_asn, network_name, country_code
        # TODO(xhdix): change versioning
        request_headers = {'user-agent': 'TraceVis/0.7.0 (WikiCensorship)'}
        if os.geteuid() == 0:
            usereuid = os.geteuid()
            os.seteuid(65534)  # user id of the user "nobody"
        with requests.get('https://speed.cloudflare.com/meta',
                          headers=request_headers, timeout=9) as meta_request:
            if meta_request.status_code == 200:
                user_meta = meta_request.json()
                public_ip = user_meta['clientIp']
                network_asn = "AS" + str(user_meta['asn'])
                network_name = user_meta['asOrganization']
                country_code = user_meta['country']
                print("· · · - · " + public_ip)
                print("· · · - · " + network_asn)
                print("· · · - · " + network_name)
                print("· · · - · " + country_code)
        if usereuid != None:
            os.seteuid(usereuid)
        return no_interent, public_ip, network_asn, network_name, country_code
    except Exception as e:
        no_interent = True
        print(f"Notice!\n{e!s}")
        if usereuid != None:
            os.seteuid(usereuid)
        return no_interent, public_ip, network_asn, network_name, country_code
