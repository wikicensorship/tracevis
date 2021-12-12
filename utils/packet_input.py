#!/usr/bin/env python3
from scapy.layers.inet import IP
from scapy.utils import import_hexcap


def yesno_second_packet(question):
    prompt = f'{question} ? (y/n): '
    answer = input(prompt).strip().lower()
    if answer not in ['y', 'n']:
        print(f'{answer} is invalid, please try again...')
        return yesno_second_packet(question)
    if answer == 'y':
        return True
    return False


def copy_input_packets():
    copy_packet_1 = ""
    copy_packet_2 = ""
    print(
        " ********************************************************************** ")
    print(
        " paste here the first packet hex dump start with the IP layer and then enter :")
    copy_packet_1 = IP(import_hexcap())
    print(" · - · - ·     · - · - ·     · - · - ·     · - · - · ")
    if yesno_second_packet("Would you like to add a second packet"):
        print(
            " paste here the second packet hex dump start with the IP layer and then enter (optional) :")
        copy_packet_2 = IP(import_hexcap())
    return copy_packet_1, copy_packet_2
