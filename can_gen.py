import can
import time
import random
import traceback

period = 0.1 # in secs
burst_prob = 0.2

def send_periodic():
    msg = can.Message(
        arbitration_id=0x100,
        data=[0x00]*8,
        is_extended_id=False
    )
    bus.send(msg)

def send_burst():
    msg = can.Message(
        arbitration_id=0x200,
        data=[0x01]*8,
        is_extended_id=False
    )
    bus.send(msg)

if __name__ == '__main__':
    try:
        bus = can.interface.Bus(channel="vcan0", interface="socketcan")

        while True:
            send_periodic()

            # send a burst can message at random
            if random.random() < burst_prob:
                time.sleep(0.001)
                send_burst()

            time.sleep(0.5)
    
    except KeyboardInterrupt:
        pass

    except Exception as e:
        print(f"Exception occured: {traceback.format_exc()}")

    finally:
        bus.shutdown()
