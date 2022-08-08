#!/usr/bin/env python3

def show_ifaces():
    from scapy.all import IFACES
    print(IFACES)


def get_iface_object(name_or_index):
    from scapy.all import IFACES
    if name_or_index == "":
        print("please set a correct iface name or index number")
        show_ifaces()
        exit(1)
    else:
        iface_object = None
        try:
            iface_index = int(name_or_index)
            iface_object = IFACES.dev_from_index(iface_index)
        except ValueError:
            iface_object = IFACES.dev_from_name(name_or_index)
        except:
            raise
        return iface_object
