from scapy.all import *
from dissectors.acf_can import ACF_CAN

ACF_MSG_TYPES = {1: ACF_CAN}


def choose_cls(packet, **kwargs):
    cls = ACF_MSG_TYPES.get(packet[0] >> 1, Raw)
    return cls(packet, **kwargs)


# define a custom packet dissector for AVTP NTSCF header
class NTSCF(Packet):
    name = "NTSCF"
    fields_desc = [
        BitField("subtype", 0, 8),
        BitField("stream_valid", 0, 1),
        BitField("version", 0, 3),
        BitField("rsv", 0, 1),
        BitField("data_length", 0, 11),
        BitField("sequence_num", 0, 8),
        BitField("stream_id", 0, 64),
        PacketListField(
            "acf_tlv", [], choose_cls, length_from=lambda pkt: pkt.data_length
        ),
    ]


bind_layers(scapy.layers.l2.Ether, NTSCF, type=0x22F0)
