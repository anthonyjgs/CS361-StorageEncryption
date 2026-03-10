import zmq
import json
from cryptography.fernet import Fernet


HOST = "localhost"
PORT = 55059


class PreparedRequest:
    action = None
    key = None
    data = None


class Response:
    status = "NOT_SET"
    data = None


def main():
    print("Data Encryption Service")
    print("Initializing...")
    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.bind(f"tcp://{HOST}:{PORT}")
    print(f"Listening on {HOST}:{PORT}")

    try:
        while True:
            service_listen(socket)
    except KeyboardInterrupt:
        print("Shutting down...")
        socket.close()


def service_listen(socket):
    """ Listens for an incoming requests to process, and sends a response. """
    req = socket.recv()
    print("Received request:", req)

    rep = Response()
    prepared_request = parse_request(req)
    if prepared_request is not None:
        process_request(prepared_request, rep)
    else:
        rep.data = "COULD NOT PARSE REQUEST"
        rep.status = "FAIL"

    socket.send(rep)

def encrypt_data(key, data):
    """ Given a key and data, encrypt it and return the encrypted data. """
    cipher = Fernet(key)
    return cipher.encrypt(data)


def decrypt_data(key, data):
    """ Given a key and data previously encrypted with it, return the decrypted
        data. """
    cipher = Fernet(key)
    return cipher.decrypt(data)


def parse_request(req) -> PreparedRequest|None:
    """ Parses the request as JSON and Returns a Prepared Request. Returns
        None if the request cannot be parsed or if fields are missing. """
    try:
        json_data = json.loads(req.data)
    except json.decoder.JSONDecodeError:
        return None

    prepared_request = PreparedRequest()
    try:
        prepared_request.action = json_data["action"]
        prepared_request.key = json_data["key"]
        prepared_request.data = json_data["data"]
    except KeyError:
        return None

    return prepared_request


def process_request(prepared_request: PreparedRequest, rep: Response) -> Response|None:
    """ Processes the request and stores the resulting status and data in
        rep. """
    action = prepared_request.action
    key = prepared_request.key
    data = prepared_request.data

    if action == "encrypt":
        rep.data = encrypt_data(key, data)
        rep.status = "OK"
    elif action == "decrypt":
        rep.data = decrypt_data(key, data)
        rep.status = "OK"
    else:
        rep.data = "UNKOWN ACTION"
        rep.status = "FAIL"

    return rep

if __name__ == "__main__":
    main()