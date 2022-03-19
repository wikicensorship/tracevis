#!/usr/bin/env python3
from struct import pack
from scapy.layers.inet import IP, TCP
from scapy.utils import import_hexcap
import json 

firewall_commands_help = "\r\n( · - · · · \r\n\
You may need to temporarily block RST output packets in your firewall.\r\n\
For example:\r\n\
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP\r\n\
After the test, you can delete it:\r\n\
iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP\r\n · - · - · )\r\n\
    "
class BADPacket(Exception):
    ...

def yesno_second_packet(question):
    prompt = f'{question} (y/n): '
    answer = input(prompt).strip().lower()
    if answer not in ['y', 'n']:
        print(f'{answer} is invalid, please try again...')
        return yesno_second_packet(question)
    if answer == 'y':
        return True
    return False


def supported_or_correct(copied_packet):
    return (copied_packet[IP].version == 4)



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
    # todo xhdix: we should have better solution
    if not supported_or_correct(copy_packet_1):
        print(" · · · · · · · · it's not IPv4 or the hexdump is not started with IP layer")
        print(
            " · · · · · · · · please check the packet and try again. ( •_•)>⌐■-■ exiting.. ")
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
            if not supported_or_correct(copy_packet_1):
                print(
                    " · · · · · · · · it's not IPv4 or the hexdump is not started with IP layer")
                print(
                    " · · · · · · · · please check the packet and try again. ( •_•)>⌐■-■ exiting.. ")
                print(" . . . - .     . . . - .     . . . - .     . . . - . ")
            if copy_packet_2.haslayer(TCP):
                if copy_packet_2[TCP].flags == "PA":
                    do_tcph2 = yesno_second_packet(
                        "Would you like to do a TCP Handshake before sending this packet?")
    print(
        " ********************************************************************** ")
    return copy_packet_1, copy_packet_2, do_tcph1, do_tcph2


def read_input_packets(os_name: str, trace_retransmission: bool, file: str):
    copy_packet_1 = ""
    copy_packet_2 = ""
    do_tcph1 = False
    do_tcph2 = False
    try:
        with open(file) as f:
            json_config = json.load(f) 
        copy_packet_1 = IP(import_hexcap(json_config['packet1']['hex']))
        print(" . . . - .     . . . - .     . . . - .     . . . - . ")
        print(" . . . - . developed view of first packet:")
        copy_packet_1.show()
        print(" . . . - .     . . . - .     . . . - .     . . . - . ")
        # todo xhdix: we should have better solution
        if not supported_or_correct(copy_packet_1):
            print(" · · · · · · · · it's not IPv4 or the hexdump is not started with IP layer")
            print(
                " · · · · · · · · please check the packet and try again. ( •_•)>⌐■-■ exiting.. ")
            print(" . . . - .     . . . - .     . . . - .     . . . - . ")
        if not trace_retransmission:
            if copy_packet_1.haslayer(TCP):
                if copy_packet_1[TCP].flags == "PA":
                    do_tcph1 = json_config['packet1'].get('handshake', False)
            if 'packet2' in json_config:
                copy_packet_2 = IP(import_hexcap(json_config['packet2']['hex']))
                print(" . . . - .     . . . - .     . . . - .     . . . - . ")
                print(" . . . - . developed view of this packet:")
                copy_packet_2.show()
                print(" . . . - .     . . . - .     . . . - .     . . . - . ")
                if not supported_or_correct(copy_packet_1):
                    print(
                        " · · · · · · · · it's not IPv4 or the hexdump is not started with IP layer")
                    print(
                        " · · · · · · · · please check the packet and try again. ( •_•)>⌐■-■ exiting.. ")
                    print(" . . . - .     . . . - .     . . . - .     . . . - . ")
                if copy_packet_2.haslayer(TCP):
                    if copy_packet_2[TCP].flags == "PA":
                        do_tcph2 = json_config['packet2'].get('handshake', False)
        print(
            " ********************************************************************** ")
    except FileNotFoundError:
        print(f" · · · · · · · · file '{file}' not found!.")
        raise BADPacket("File Not Found")
    return copy_packet_1, copy_packet_2, do_tcph1, do_tcph2


def read_input_packets_scapy(os_name: str, trace_retransmission: bool):
    from scapy.layers.inet import IP, TCP
    from scapy.utils import import_hexcap

    copy_packet_1 = ""
    copy_packet_2 = ""
    do_tcph1 = False
    do_tcph2 = False
    banner = "Please create your packet in variable \"p\" and exit when you are done"
    try:
        from IPython.terminal.embed import InteractiveShellEmbed
        ipshell = InteractiveShellEmbed(banner1=banner, user_ns=locals())
        ipshell()
        copy_packet_1 = ipshell.user_ns['p']
    except:
        # FIXME: Make this work with default console 
        raise NotImplementedError("Currently Only IPython Console is supported!")
        import code
        code.interact(banner=banner, local=locals())
        copy_packet_1 = p 
    print(" . . . - .     . . . - .     . . . - .     . . . - . ")
    print(" . . . - . developed view of first packet:")
    copy_packet_1.show()
    print(" . . . - .     . . . - .     . . . - .     . . . - . ")
    # todo xhdix: we should have better solution
    if not supported_or_correct(copy_packet_1):
        print(" · · · · · · · · it's not IPv4 or the hexdump is not started with IP layer")
        print(
            " · · · · · · · · please check the packet and try again. ( •_•)>⌐■-■ exiting.. ")
        print(" . . . - .     . . . - .     . . . - .     . . . - . ")
        raise BADPacket("Invalid Packet!")
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
        if yesno_second_packet("Would you like to add a second packet"):
            banner = "Please create your packet in variable \"p\" and exit when you are done"
            try:
                from IPython.terminal.embed import InteractiveShellEmbed
                ipshell = InteractiveShellEmbed(banner1=banner, user_ns=locals())
                ipshell()
                copy_packet_2 = ipshell.user_ns['p']
            except:
                # FIXME: Make this work with default console 
                raise NotImplementedError("Currently Only IPython Console is supported!")
                import code
                code.interact(banner=banner, local=locals())
                copy_packet_2 = p
            print(" . . . - .     . . . - .     . . . - .     . . . - . ")
            print(" . . . - . developed view of this packet:")
            copy_packet_2.show()
            print(" . . . - .     . . . - .     . . . - .     . . . - . ")
            if not supported_or_correct(copy_packet_1):
                print(
                    " · · · · · · · · it's not IPv4 or the hexdump is not started with IP layer")
                print(
                    " · · · · · · · · please check the packet and try again. ( •_•)>⌐■-■ exiting.. ")
                print(" . . . - .     . . . - .     . . . - .     . . . - . ")
                raise BADPacket("Invalid Packet!")
            if copy_packet_2.haslayer(TCP):
                if copy_packet_2[TCP].flags == "PA":
                    do_tcph2 = yesno_second_packet(
                        "Would you like to do a TCP Handshake before sending this packet?")
    print(
        " ********************************************************************** ")
    return copy_packet_1, copy_packet_2, do_tcph1, do_tcph2

