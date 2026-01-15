from scapy.all import *

# define a custom packet dissector for ACF CAN message
class ACF_CAN(Packet):
    name = "ACF_CAN"
    fields_desc = [
        BitField("acf_msg_type", 0, 7),
        BitField("acf_msg_length", 0, 9),
        BitField("pad", 0, 2),
        BitField("mtv", 0, 1),
        BitField("rtr", 0, 1),
        BitField("eff", 0, 1),
        BitField("brs", 0, 1),
        BitField("fdf", 0, 1),
        BitField("esi", 0, 1),
        BitField("rsv1", 0, 3),
        BitField("can_bus_id", 0, 5),
        BitField("message_timestamp", 0, 64),
        BitField("rsv2", 0, 3),
        BitField("can_id", 0, 29),
        StrLenField(
            "can_msg_payload", b"", length_from=lambda pkt: pkt.acf_msg_length * 4 - 16
        ),
    ]

    # extract payload from the remaining bytes
    def extract_padding(self, s):
        return b"", s
