#!/usr/bin/env python3
from scapy.all import *
from time import sleep
sleeptime = 1
for myttl in range(40):
    i = 0
    while i < 3:
        i += 1
        dns_request = IP(dst="8.8.8.8", id=RandShort(), ttl=myttl)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, id=RandShort(), qd=DNSQR(qname="www.google.com"))
        print(">>>request:" + "   ip.dst: " + dns_request[IP].dst + "   ip.ttl: " + str(myttl))
        req_answer = sr1(dns_request, verbose=0, timeout=3)
        if req_answer is not None:
            backttl = 0
            if req_answer[IP].ttl <= 64 :
                backttl = 64 - req_answer[IP].ttl
            elif req_answer[IP].ttl <= 128 :
                backttl = 128 - req_answer[IP].ttl
            else :
                backttl = 255 - req_answer[IP].ttl
            print("   <<< answer:" + "   ip.src: " + req_answer[IP].src + "   ip.ttl: " + str(req_answer[IP].ttl) + "   back-ttl: " + str(backttl))
            print("      " + req_answer.summary())
        else:
            print(" *** no response *** ")
        print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
        sleep(sleeptime)
        dns_request = IP(dst="8.8.4.4", id=RandShort(), ttl=myttl)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, id=RandShort(), qd=DNSQR(qname="www.google.com"))
        print(">>>request:" + "   ip.dst: " + dns_request[IP].dst + "   ip.ttl: " + str(myttl))
        req_answer = sr1(dns_request, verbose=0, timeout=3)
        if req_answer is not None:
            backttl = 0
            if req_answer[IP].ttl <= 64 :
                backttl = 64 - req_answer[IP].ttl
            elif req_answer[IP].ttl <= 128 :
                backttl = 128 - req_answer[IP].ttl
            else :
                backttl = 255 - req_answer[IP].ttl
            print("   <<< answer:" + "   ip.src: " + req_answer[IP].src + "   ip.ttl: " + str(req_answer[IP].ttl) + "   back-ttl: " + str(backttl))
            print("      " + req_answer.summary())
        else:
            print(" *** no response *** ")
        print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
        sleep(sleeptime)
        dns_request = IP(dst="4.2.2.4", id=RandShort(), ttl=myttl)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, id=RandShort(), qd=DNSQR(qname="www.google.com"))
        print(">>>request:" + "   ip.dst: " + dns_request[IP].dst + "   ip.ttl: " + str(myttl))
        req_answer = sr1(dns_request, verbose=0, timeout=3)
        if req_answer is not None:
            backttl = 0
            if req_answer[IP].ttl <= 64 :
                backttl = 64 - req_answer[IP].ttl
            elif req_answer[IP].ttl <= 128 :
                backttl = 128 - req_answer[IP].ttl
            else :
                backttl = 255 - req_answer[IP].ttl
            print("   <<< answer:" + "   ip.src: " + req_answer[IP].src + "   ip.ttl: " + str(req_answer[IP].ttl) + "   back-ttl: " + str(backttl))
            print("      " + req_answer.summary())
        else:
            print(" *** no response *** ")
        print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
        print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
        print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
        sleep(sleeptime)
    print(" ********************************************************************** ")
    dns_request = IP(dst="8.8.8.8", id=RandShort(), ttl=myttl)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, id=RandShort(), qd=DNSQR(qname="www.twitter.com"))
    print(">>>request:" + "   ip.dst: " + dns_request[IP].dst + "   ip.ttl: " + str(myttl))
    req_answer = sr1(dns_request, verbose=0, timeout=3)
    if req_answer is not None:
        backttl = 0
        if req_answer[IP].ttl <= 64 :
            backttl = 64 - req_answer[IP].ttl
        elif req_answer[IP].ttl <= 128 :
            backttl = 128 - req_answer[IP].ttl
        else :
            backttl = 255 - req_answer[IP].ttl
        print("   <<< answer:" + "   ip.src: " + req_answer[IP].src + "   ip.ttl: " + str(req_answer[IP].ttl) + "   back-ttl: " + str(backttl))
        print("      " + req_answer.summary())
    else:
        print(" *** no response *** ")
    print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
    sleep(sleeptime)
    dns_request = IP(dst="8.8.4.4", id=RandShort(), ttl=myttl)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, id=RandShort(), qd=DNSQR(qname="www.twitter.com"))
    print(">>>request:" + "   ip.dst: " + dns_request[IP].dst + "   ip.ttl: " + str(myttl))
    req_answer = sr1(dns_request, verbose=0, timeout=3)
    if req_answer is not None:
        backttl = 0
        if req_answer[IP].ttl <= 64 :
            backttl = 64 - req_answer[IP].ttl
        elif req_answer[IP].ttl <= 128 :
            backttl = 128 - req_answer[IP].ttl
        else :
            backttl = 255 - req_answer[IP].ttl
        print("   <<< answer:" + "   ip.src: " + req_answer[IP].src + "   ip.ttl: " + str(req_answer[IP].ttl) + "   back-ttl: " + str(backttl))
        print("      " + req_answer.summary())
    else:
        print(" *** no response *** ")
    print(" · · · − − − · · ·     · · · − − − · · ·     · · · − − − · · · ")
    sleep(sleeptime)
    dns_request = IP(dst="1.1.1.1", id=RandShort(), ttl=myttl)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, id=RandShort(), qd=DNSQR(qname="www.twitter.com"))
    print(">>>request:" + "   ip.dst: " + dns_request[IP].dst + "   ip.ttl: " + str(myttl))
    req_answer = sr1(dns_request, verbose=0, timeout=3)
    if req_answer is not None:
        backttl = 0
        if req_answer[IP].ttl <= 64 :
            backttl = 64 - req_answer[IP].ttl
        elif req_answer[IP].ttl <= 128 :
            backttl = 128 - req_answer[IP].ttl
        else :
            backttl = 255 - req_answer[IP].ttl
        print("   <<< answer:" + "   ip.src: " + req_answer[IP].src + "   ip.ttl: " + str(req_answer[IP].ttl) + "   back-ttl: " + str(backttl))
        print("      " + req_answer.summary())
    else:
        print(" *** no response *** ")
    sleep(sleeptime)
    print(" ********************************************************************** ")
    print(" ********************************************************************** ")
    print(" ********************************************************************** ")

