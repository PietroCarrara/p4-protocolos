#!/usr/bin/env python3

# ----------------- REGION: SETUP -----------------
# |            You can ignore this code           |
# -------------------------------------------------
import os
import sys
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
# -------------- END OF REGION: SETUP -------------
# |        You can ignore the code above code     |
# -------------------------------------------------

TELEMETRY_ETHER_TYPE = 0x801
SIZEOF_TELEMETRY_ITEM = (48 + 9 + 9 + 6) // 8 # Sizeof in bytes

def handle_pkt(pkt: Packet):
    if Ether in pkt and pkt[Ether].type == TELEMETRY_ETHER_TYPE:
        telemetry_item_count = pkt[Raw].load[0]
        telemetry_items_buffer = BitReader(pkt[Raw].load[1:1+telemetry_item_count*SIZEOF_TELEMETRY_ITEM])
        telemetry_items = []

        for i in range(telemetry_item_count):
            telemetry_items.append({
                "ingress_global_timestamp": telemetry_items_buffer.read(48),
                "ingress_port": telemetry_items_buffer.read(9),
                "egress_port": telemetry_items_buffer.read(9),
                "switch_id": telemetry_items_buffer.read(6),
            })

        rest_of_packet = pkt[Raw].load[1+telemetry_item_count*SIZEOF_TELEMETRY_ITEM:]
        ip_packet = IP(rest_of_packet)

        display_metrics(telemetry_items)
        ip_packet.show2()
        print()

def display_metrics(metrics):
    for switch in metrics:
        print(f"# Switch {switch["switch_id"]}")
        print(f"  - Ingress Timestamp: {switch["ingress_global_timestamp"]} (microseconds)")
        print(f"  - Ingress Port:      {switch["ingress_port"]}")
        print(f"  - Egress Port:       {switch["egress_port"]}")

# Big-endian bit reader
class BitReader:
    def __init__(self, buffer: bytes):
        self.position = 0
        self.buffer = buffer

    def read(self, n: int) -> int:
        total = 0

        for i in range(n):
            total = total << 1

            current_byte = self.position // 8
            offset_within_byte = self.position % 8

            byte = self.buffer[current_byte]
            bit = byte & (1 << (7-offset_within_byte))

            if bit != 0:
                total += 1

            self.position += 1

        return total


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
