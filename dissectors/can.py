from scapy.all import *


# define a custom packet dissector for CAN
class CAN(Packet):
    name = "CAN"
    fields_desc = [
        BitField("can_id", 0, 29),
        BitField("extended", 0, 1),
        BitField("rtr", 0, 1),
        BitField("err", 0, 1),
        BitField("dlc", 0, 8),
        BitField("rsv", 0, 24),
        XBitField("data", 0, 64),
    ]
