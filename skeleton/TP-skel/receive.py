#!/usr/bin/env python3
import os
import sys

TELEMETRY_ETHER_TYPE = 0x801
SIZEOF_TELEMETRY_ITEM = 48 + 9 + 9 + 6

from scapy.all import (
    FieldLenField,
    FieldListField,
    IntField,
    ShortField,
    get_if_list,
    sniff,
)
from scapy.layers.inet import _IPOption_HDR, IP, IPOption
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from binascii import hexlify


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt: Packet):
    if Ether in pkt and pkt[Ether].type == TELEMETRY_ETHER_TYPE:
        telemetry_item_count = pkt[Raw].load[0]
        telemetry_items = pkt[Raw].load[1:1+telemetry_item_count*SIZEOF_TELEMETRY_ITEM]
        # TODO: Parse!

        rest_of_packet = pkt[Raw].load[1+telemetry_item_count*SIZEOF_TELEMETRY_ITEM:]
        ip_packet = IP(rest_of_packet)

        print(f'Telemetry raw data: {repr(hexlify(telemetry_items, '-'))}')
        ip_packet.show2()
        print()



def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
