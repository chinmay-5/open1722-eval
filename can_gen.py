import can
import time
import random
import traceback

period = 0.1  # in secs
burst_prob = 0.2


def send_periodic():
    can_id = random.randint(0x000, 0x7FF)  # 11-bits
    msg = can.Message(arbitration_id=can_id, data=[0x00] * 8, is_extended_id=False)
    bus.send(msg)


def send_burst():
    can_id = random.randint(0x000, 0x7FF)  # 11-bits
    msg = can.Message(arbitration_id=can_id, data=[0x01] * 8, is_extended_id=False)
    bus.send(msg)


if __name__ == "__main__":
    try:
        bus = can.interface.Bus(channel="vcan0", interface="socketcan")

        while True:
            for i in range(3):
                send_periodic()
                time.sleep(0.01)

            time.sleep(0.5)

            # send a burst can message at random
            # if random.random() < burst_prob:
            # for i in range(3):
            #     send_burst()
            #     time.sleep(0.1)

            # time.sleep(1)

    except KeyboardInterrupt:
        pass

    except Exception as e:
        print(f"Exception occured: {traceback.format_exc()}")

    finally:
        bus.shutdown()
