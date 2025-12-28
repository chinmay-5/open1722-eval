import sys
import threading
from scapy.all import *
from dissectors.can import CAN

frames_buffer = {}

def run_sniffer():
    """
    Initializes a async scapy sniffer for vcan ifaces. 
    """
    print('Initializing scapy sniffer..')
    sniffer = AsyncSniffer(iface=['vcan0', 'vcan1'], prn=lambda x: process_packet(x))
    sniffer.start()

def process_packet(pkt: Packet):
    """
    Dissects the CAN frame and adds it to the frame buffer. 
    """
    can_frame = CAN(raw(pkt))
    can_frame.time = pkt.time
    can_id = can_frame.can_id

    if can_id not in list(frames_buffer.keys()):
        frames_buffer[can_id] = []
        if pkt.sniffed_on == 'vcan0':
            frames_buffer[can_id].append(can_frame)
        else:
            pass
    else:
        # resolve duplicates in case of lo iface
        if pkt.sniffed_on == 'vcan1':
            frames_buffer[can_id].append(can_frame)
            if len(frames_buffer[can_id]) == 3:
                frames_buffer[can_id].pop(1)
                process_txn(frames_buffer[can_id])

def process_txn(txn):
    """
    Finds the transmission latency of the CAN frame. 
    """
    sent = txn[0]
    recv = txn[-1]
    print(f'latency: {(recv.time - sent.time)*1e3} ms')
    
if __name__ == '__main__':
    try:
        if 'vcan0' and 'vcan1' in scapy.interfaces.get_if_list():
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
