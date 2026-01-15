import zmq

def setup_socket(port=5556):
    context = zmq.Context()
    socket = context.socket(zmq.PUB)
    # socket.bind(f"tcp://127.0.0.1:{port}")
    socket.bind("ipc:///tmp/metrics.pub")

    return socket

def publish_message(socket, topic: int | str, message: int | str, key=None):
    payload = [str(topic), str(message)]
    if key:
        payload.append(str(key))
    # print(" ".join(payload))

    socket.send_multipart([p.encode("utf8") for p in payload])
