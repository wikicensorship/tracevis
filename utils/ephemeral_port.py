#!/usr/bin/env python3

import contextlib
import socket

from scapy.all import conf, get_if_addr

SOURCE_IP_ADDRESS = get_if_addr(conf.iface)

# ephemeral_port_reserve() function is based on https://github.com/Yelp/ephemeral-port-reserve


def ephemeral_port_reserve(proto: str = "tcp"):
    socketkind = socket.SOCK_STREAM
    ipproto = socket.IPPROTO_TCP
    if proto == "udp":
        socketkind = socket.SOCK_DGRAM
        ipproto = socket.IPPROTO_UDP
    with contextlib.closing(socket.socket(socket.AF_INET, socketkind, ipproto)) as s:
        s.bind((SOURCE_IP_ADDRESS, 0))
        # the connect below deadlocks on kernel >= 4.4.0 unless this arg is greater than zero
        if proto == "tcp":
            s.listen(1)
        sockname = s.getsockname()
        # these three are necessary just to get the port into a TIME_WAIT state
        with contextlib.closing(socket.socket(socket.AF_INET, socketkind, ipproto)) as s2:
            s2.connect(sockname)
            if proto == "tcp":
                sock, _ = s.accept()
                with contextlib.closing(sock):
                    return sockname[1]
            with contextlib.closing(s2):
                return sockname[1]
