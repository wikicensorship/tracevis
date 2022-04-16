#!/usr/bin/env python3
from scapy.layers.inet import IP, TCP
from scapy.utils import import_hexcap
import subprocess
import base64
import json 


FIREWALL_COMMANDS_HELP = "\r\n( · - · · · \r\n\
You may need to temporarily block RST output packets in your firewall.\r\n\
For example:\r\n\
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP\r\n\
After the test, you can delete it:\r\n\
iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP\r\n · - · - · )\r\n" 


class BADPacketException(Exception):
    """ An Exception which is thrown on bad packets """
    ...

class FirewallException(Exception):
    """ An Exception which is thrown on firewall errors """
    ...


class InputPacketInfo:
    def __init__(self, packet1, packet2, do_tcph1, do_tcph2, add_firewall_rule):
        self._packet1 = packet1
        self._packet2 = packet2
        self._do_tcph1 = do_tcph1
        self._do_tcph2 = do_tcph2
        self._add_firewall_rule = add_firewall_rule

    @property
    def params(self):
         return (self._packet1 or "", self._packet2 or "", self._do_tcph1, self._do_tcph2)

    def __enter__(self):
        if self._add_firewall_rule:
            self._add_firewal_out_drop_rule()
        return self.params 

    def __exit__(self, *args, **kwargs):
        if self._add_firewall_rule:
            self._remove_firewal_out_drop_rule()

    @classmethod
    def _iptables_exists(cls):
        try:
            p = subprocess.run([ 'iptables', '-L', '-n'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False

    @classmethod
    def _check_firewal_out_drop_rule(cls):
        try:
            p = subprocess.run([ 'iptables', '-C', 'OUTPUT', '-p', 'tcp', 
                                '--tcp-flags', 'RST', 'RST', '-j', 'DROP'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False

    @classmethod
    def _add_firewal_out_drop_rule(cls):
        try:
            p = subprocess.run([ 'iptables', '-A', 'OUTPUT', '-p', 'tcp', 
                                '--tcp-flags', 'RST', 'RST', '-j', 'DROP'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if not cls._check_firewal_out_drop_rule():
                raise FirewallException("Added DROP rule cannot be verified")
            return True
        except subprocess.CalledProcessError:
            raise FirewallException("Adding DROP rule failed")
            
    @classmethod
    def _remove_firewal_out_drop_rule(cls):
        try:
            p = subprocess.run([ 'iptables', '-D', 'OUTPUT', '-p', 'tcp', 
                                '--tcp-flags', 'RST', 'RST', '-j', 'DROP'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if cls._check_firewal_out_drop_rule():
                raise FirewallException("Removing DROP rule cannot be verified")
            return True
        except subprocess.CalledProcessError:
            raise FirewallException("Removing DROP rule failed")


    @classmethod
    def _ask_yesno(cls, question):
        prompt = f'{question} (y/n): '
        answer = input(prompt).strip().lower()
        if answer not in ['y', 'n']:
            print(f'{answer} is invalid, please try again...')
            return cls._ask_yesno(question)
        if answer == 'y':
            return True
        return False


    @classmethod
    def _supported_or_correct(cls, copied_packet):
        return (copied_packet[IP].version == 4)


    @classmethod
    def _read_pasted_packet(cls, show=False):
        print(" ********************************************************************** ")
        print(" paste here the packet hex dump start with the IP layer and then enter :")
        print(" . . . - .     . . . - .     . . . - .     . . . - . ")
        p1 = IP(import_hexcap())
        print(" . . . - .     . . . - .     . . . - .     . . . - . ")
        if not  cls._supported_or_correct(p1):
            raise BADPacketException("it's not IPv4 or the hexdump is not started with IP layer")
        if show:
            print(" . . . - . developed view of this packet:")
            p1.show()
            print(" . . . - .     . . . - .     . . . - .     . . . - . ")
        return p1



    @classmethod
    def from_stdin(cls, os_name: str, trace_retransmission: bool):
        copy_packet_1 :'scapy.layers.inet.Packet' = None
        copy_packet_2 :'scapy.layers.inet.Packet' = None
        do_tcph1 :bool = False
        do_tcph2 :bool = False
        add_firewall_rule = False

        copy_packet_1 = cls._read_pasted_packet(True)
        if not trace_retransmission:
            if copy_packet_1.haslayer(TCP) and copy_packet_1[TCP].flags == "PA":
                if os_name.lower() == "linux":
                    if cls._iptables_exists():
                        do_tcph1 = cls._ask_yesno(f"Would you like to do a TCP Handshake before sending this packet?")
                        if not cls._check_firewal_out_drop_rule():
                            add_firewall_rule = cls._ask_yesno(f"{FIREWALL_COMMANDS_HELP}\n\nDo You want add rules automaticallly?")
                    else:
                        # FIXME: WHAT IF NOT? FAIL?
                        raise FirewallException("No iptables!")
                else:
                    do_tcph1 = cls._ask_yesno("Would you like to do a TCP Handshake before sending this packet?")
                print(" · - · - ·     · - · - ·     · - · - ·     · - · - · ")

                    
            if cls._ask_yesno("Would you like to add a second packet"):
                copy_packet_2 = cls._read_pasted_packet(True)
                if copy_packet_2.haslayer(TCP):
                    if copy_packet_2[TCP].flags == "PA":
                        do_tcph2 = cls._ask_yesno("Would you like to do a TCP Handshake before sending this packet?")
        print(" ********************************************************************** ")
        return InputPacketInfo(copy_packet_1, copy_packet_2, do_tcph1,  do_tcph2, add_firewall_rule)

    @classmethod
    def _read_json_packet(cls, json_config, k, show=False):
        if json_config[k]['hex'].startswith("b64:"):
            json_config[k]['hex'] = base64.b64decode(json_config[k]['hex'][4:].strip()).decode()
        packet = IP(import_hexcap(json_config[k]['hex']))
        print(" . . . - .     . . . - .     . . . - .     . . . - . ")
        print(" . . . - . developed view of first packet:")
        if not cls._supported_or_correct(packet):
            BADPacketException(f"{k} it's not IPv4 or the hexdump is not started with IP layer")
        if show:
            packet.show()
            print(" . . . - .     . . . - .     . . . - .     . . . - . ")
        return packet
        
    @classmethod
    def from_json(cls, os_name: str, trace_retransmission: bool, packet_data: json):
        copy_packet_1 :'scapy.layers.inet.Packet' = None
        copy_packet_2 :'scapy.layers.inet.Packet' = None
        do_tcph1 :bool = False
        do_tcph2 :bool = False
        add_firewall_rule = False

        try:
            json_config = packet_data
            copy_packet_1 = cls._read_json_packet(json_config, 'packet1', show=True)
            if not trace_retransmission:
                if copy_packet_1.haslayer(TCP):
                    if copy_packet_1[TCP].flags == "PA":
                        do_tcph1 = json_config['packet1'].get('handshake', False)
                if 'packet2' in json_config:
                    copy_packet_2 = cls._read_json_packet(json_config, 'packet2', show=True)
                    if copy_packet_2.haslayer(TCP):
                        if copy_packet_2[TCP].flags == "PA":
                            do_tcph2 = json_config['packet2'].get('handshake', False)
            add_firewall_rule = json_config.get('add_firewall_drop', False)            
            print(" ********************************************************************** ")
        except FileNotFoundError:
            print(f" · · · · · · · · file '{file}' not found!.")
            raise BADPacketException("File Not Found")
        return InputPacketInfo(copy_packet_1, copy_packet_2, do_tcph1,  do_tcph2, add_firewall_rule)

    @classmethod
    def _read_interactive_packet(cls, show=False):
        from scapy.layers.inet import IP, TCP
        banner = "Please create your packet in variable \"p\" and exit when you are done"
        try:
            from IPython.terminal.embed import InteractiveShellEmbed
            ipshell = InteractiveShellEmbed(banner1=banner, user_ns=locals())
            ipshell()
            packet = ipshell.user_ns['p']
        except:
            # FIXME: Make this work with default console 
            raise NotImplementedError("Currently Only IPython Console is supported!")
            import code
            code.interact(banner=banner, local=locals())
            packet = p 

        if not cls._supported_or_correct(packet):
            raise BADPacketException("it's not IPv4 or the hexdump is not started with IP layer")
        if show:
            print(" . . . - .     . . . - .     . . . - .     . . . - . ")
            print(" . . . - . developed view of first packet:")
            packet.show()
            print(" . . . - .     . . . - .     . . . - .     . . . - . ")
        return packet

    @classmethod
    def from_scapy(cls, os_name: str, trace_retransmission: bool):
        copy_packet_1 = ""
        copy_packet_2 = ""
        do_tcph1 = False
        do_tcph2 = False
        add_firewall_rule = False


        copy_packet_1 = cls._read_interactive_packet(show=True)
        if not trace_retransmission:
            if os_name.lower() == "linux":
                if cls._iptables_exists():
                    do_tcph1 = cls._ask_yesno(f"Would you like to do a TCP Handshake before sending this packet?")
                    if not cls._check_firewal_out_drop_rule():
                        add_firewall_rule = cls._ask_yesno(f"{FIREWALL_COMMANDS_HELP}\n\nDo You want add rules automaticallly?")
                else:
                    # FIXME: WHAT IF NOT? FAIL?
                    raise FirewallException("No iptables!")
            else:
                do_tcph1 = cls._ask_yesno("Would you like to do a TCP Handshake before sending this packet?")
            print(" · - · - ·     · - · - ·     · - · - ·     · - · - · ")

            if cls._ask_yesno("Would you like to add a second packet"):
                copy_packet_2 = cls._read_interactive_packet(show=True)
                if copy_packet_2.haslayer(TCP) and copy_packet_2[TCP].flags == "PA":
                    do_tcph2 = cls._ask_yesno("Would you like to do a TCP Handshake before sending this packet?")
        print(" ********************************************************************** ")
        return InputPacketInfo(copy_packet_1, copy_packet_2, do_tcph1,  do_tcph2, add_firewall_rule)

