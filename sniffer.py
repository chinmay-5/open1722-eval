import sys
import threading

from scapy.all import *

from dissectors.can import CAN
from dissectors.acf_common import NTSCF
from dissectors.acf_can import ACF_CAN

from pub_server import setup_socket, publish_message

frames_buffer = {}
sniffer = None

def run_sniffer():
    """
    Initializes a async scapy sniffer for vcan ifaces. 
    """
    global sniffer

    print('Initializing scapy sniffer..')
    sniffer = AsyncSniffer(iface=['vcan0', 'lo', 'vcan1'], prn=lambda x: process_packet(x))
    sniffer.start()

def process_packet(pkt: Packet):
    """
    Dissects the CAN frame and adds it to the frame buffer. 
    """
    if pkt.sniffed_on in ['vcan0', 'vcan1']:
        can_frame = CAN(raw(pkt))
        can_frame.time = pkt.time
        can_id = can_frame.can_id

        if pkt.sniffed_on == 'vcan0':
            if can_id not in list(frames_buffer.keys()):
                frames_buffer[can_id] = [can_frame]
            else:
                pass
        else:
            # packets sniffed on vcan1
            # resolve duplicates in case of lo iface
            frames_buffer[can_id].append(can_frame)
            if len(frames_buffer[can_id]) == 3:
                frames_buffer[can_id].pop(1)
                get_latency(frames_buffer[can_id], can_id)
                frames_buffer.pop(can_id)

    elif pkt.sniffed_on == 'lo':
        if NTSCF in pkt:
            # print(pkt.show2())
            pass

def get_latency(txn, can_id):
    """
    Calculates the transmission latency of the tunneled CAN frame and publishes it. 
    """
    sent = txn[0]
    recv = txn[-1]
    latency = (recv.time - sent.time)*1e3
    print(f'latency ({can_id}): {latency} ms')
    publish_message(zmq_socket, 'latency', latency, can_id)

    return latency

if __name__ == '__main__':
    try:
        if 'vcan0' and 'vcan1' in scapy.interfaces.get_if_list():
            zmq_socket = setup_socket()

            sniffer_thread = threading.Thread(target=run_sniffer)
            sniffer_thread.start()
            while True:
                pass
        else:
            print('Virtual can interface vcan0 and vcan1 not found. Exiting..')
            sys.exit(0)
    except Exception as e:
        print(f'Error: {e}. Exiting..')
    except KeyboardInterrupt:
        print(f'Exiting..')
        if sniffer:
            sniffer.stop()
