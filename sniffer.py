import sys
import threading
import traceback
import time

from scapy.all import *

from dissectors.can import CAN
from dissectors.acf_common import NTSCF
from dissectors.acf_can import ACF_CAN

from pub_server import setup_socket, publish_message

can_buffer = {}
eth_buffer = []
sniffer = None
sniffer_ready = threading.Event()


def run_sniffer():
    """
    Initializes a async scapy sniffer for vcan ifaces.
    """
    global sniffer

    sniffer = AsyncSniffer(
        iface=["vcan0", "lo", "vcan1"], prn=lambda x: process_packet(x)
    )
    sniffer.start()
    sniffer_ready.set()


def process_packet(pkt: Packet):
    """
    Dissects the CAN / ETH frame and adds it to the frame buffer.
    """
    if pkt.sniffed_on in ["vcan0", "vcan1"]:
        can_frame = CAN(raw(pkt))
        can_frame.time = pkt.time
        can_id = can_frame.can_id

        if pkt.sniffed_on == "vcan0":
            if can_id not in list(can_buffer.keys()):
                can_buffer[can_id] = [can_frame]
            else:
                pass
        else:
            # packets sniffed on vcan1
            # resolve duplicates in case of lo iface
            can_buffer[can_id].append(can_frame)
            if len(can_buffer[can_id]) == 3:
                can_buffer[can_id].pop(1)
                get_latency(can_buffer[can_id], can_id)
                can_buffer.pop(can_id)

    elif pkt.sniffed_on == "lo":
        if NTSCF in pkt:
            get_efficiency(pkt)


def get_latency(txn, can_id):
    """
    Calculates the transmission latency of the tunneled CAN frame and publishes it.
    """
    sent = txn[0]
    recv = txn[-1]
    latency = (recv.time - sent.time) * 1e3
    print(f"latency ({can_id}): {latency} ms")
    publish_message(zmq_socket, "latency", latency, can_id)

    return latency


def get_efficiency(pkt):
    """
    Calculates the frame efficiency of the tunneled CAN frame and publishes it.
    """
    frame_efficiency = None
    duplicate = False
    payload_size = 0

    for acf_msg in pkt.acf_tlv:
        if acf_msg.can_id not in eth_buffer:
            payload_size += len(acf_msg.can_msg_payload) - acf_msg.pad
            # to avoid duplicates
            eth_buffer.append(acf_msg.can_id)
        else:
            eth_buffer.remove(acf_msg.can_id)
            duplicate = True

    if not duplicate:
        # min eth size is 64 bytes
        # ETH -> 14
        # NTSCF -> 12
        # ACF-CAN -> 24
        pkt_size = max(len(pkt), 64)
        frame_efficiency = payload_size / pkt_size

        print(f"efficiency: {frame_efficiency}")
        publish_message(zmq_socket, "efficiency", frame_efficiency)

    return frame_efficiency


if __name__ == "__main__":
    if "vcan0" and "vcan1" in scapy.interfaces.get_if_list():
        zmq_socket = setup_socket()

        sniffer_thread = threading.Thread(target=run_sniffer)
        sniffer_thread.start()

        if not sniffer_ready.wait(timeout=2.0):
            raise RuntimeError("Sniffer failed to start")

        print("Sniffer running. Press Ctrl+C to stop.")
    else:
        raise OSError("Virtual can interface vcan0 and vcan1 not found. Exiting.")

    try:
        while True:
            time.sleep(1)
    except Exception as e:
        print(f"Exception occured: {traceback.format_exc()}")
    except KeyboardInterrupt:
        print(f"Exiting.")
        if sniffer:
            sniffer.stop()
