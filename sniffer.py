import sys
import threading
from scapy.all import *
from dissectors.can import CAN

frames_buffer = []

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

    if len(frames_buffer) == 0:
        if pkt.sniffed_on == 'vcan0':
            frames_buffer.append(can_frame)
        else:
            pass
    else:
        # resolve duplicates in case of lo iface
        if can_frame not in frames_buffer:
            frames_buffer.append(can_frame)

        if pkt.sniffed_on == 'vcan1' and can_frame in frames_buffer:
            frames_buffer.remove(can_frame)
            frames_buffer.append(can_frame)
            process_txn()

def process_txn():
    """
    Finds the transaction latency from the frame buffer. 
    """
    recv = frames_buffer[-1]
    for frame in frames_buffer[:-1][::-1]:
        if frame.can_id == recv.can_id:
            print(f'latency: {(recv.time - frame.time)*1e3} ms')
            frames_buffer.remove(frame)
            frames_buffer.pop(-1)
            break
    
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
