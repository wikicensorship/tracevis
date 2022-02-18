#!/usr/bin/env python3
from scapy.layers.inet import IP, TCP
from scapy.utils import import_hexcap

firewall_commands_help = "\r\n( · - · · · \r\n\
You may need to temporarily block RST output packets in your firewall.\r\n\
For example:\r\n\
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP\r\n\
After the test, you can delete it:\r\n\
iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP\r\n · - · - · )\r\n\
    "


def yesno_second_packet(question):
    prompt = f'{question} (y/n): '
    answer = input(prompt).strip().lower()
    if answer not in ['y', 'n']:
        print(f'{answer} is invalid, please try again...')
        return yesno_second_packet(question)
    if answer == 'y':
        return True
    return False


def copy_input_packets(os_name: str, trace_retransmission: bool):
    copy_packet_1 = ""
    copy_packet_2 = ""
    do_tcph1 = False
    do_tcph2 = False
    print(
        " ********************************************************************** ")
    print(
        " paste here the first packet hex dump start with the IP layer and then enter :")
    print(" . . . - .     . . . - .     . . . - .     . . . - . ")
    copy_packet_1 = IP(import_hexcap())
    print(" . . . - .     . . . - .     . . . - .     . . . - . ")
    print(" . . . - . developed view of this packet:")
    copy_packet_1.show()
    print(" . . . - .     . . . - .     . . . - .     . . . - . ")
    if not trace_retransmission:
        if copy_packet_1.haslayer(TCP):
            if copy_packet_1[TCP].flags == "PA":
                if os_name == "Linux":
                    do_tcph1 = yesno_second_packet(
                        "Would you like to do a TCP Handshake before sending this packet?"
                        + firewall_commands_help)
                else:
                    do_tcph1 = yesno_second_packet(
                        "Would you like to do a TCP Handshake before sending this packet?")
                print(" · - · - ·     · - · - ·     · - · - ·     · - · - · ")
        if yesno_second_packet("Would you like to add a second packet"):
            print(
                " paste here the second packet hex dump start with the IP layer and then enter (optional) :")
            print(" . . . - .     . . . - .     . . . - .     . . . - . ")
            copy_packet_2 = IP(import_hexcap())
            print(" . . . - .     . . . - .     . . . - .     . . . - . ")
            print(" . . . - . developed view of this packet:")
            copy_packet_2.show()
            print(" . . . - .     . . . - .     . . . - .     . . . - . ")
            if copy_packet_2.haslayer(TCP):
                if copy_packet_2[TCP].flags == "PA":
                    do_tcph2 = yesno_second_packet(
                        "Would you like to do a TCP Handshake before sending this packet?")
    print(
        " ********************************************************************** ")
    return copy_packet_1, copy_packet_2, do_tcph1, do_tcph2
