import zmq
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


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
    socket.bind(f"tcp://localhost:{PORT}")
    print(f"Listening on port {PORT}")

    try:
        while True:
            service_listen(socket)
    except KeyboardInterrupt:
        print("Shutting down...")
        socket.close()


def service_listen(socket):
    """ Listens for an incoming requests to process, and sends a response. """
    # TODO: Check and handle errors for bad json input
    req = socket.recv_json()
    print("Received request:", req)

    rep = Response()
    prepared_request = parse_request(req)
    if prepared_request is not None:
        process_request(prepared_request, rep)
    else:
        rep.data = "COULD NOT PARSE REQUEST"
        rep.status = "FAIL"

    socket.send_json({"status": rep.status, "data": rep.data})

def key_encode(key_bytes:bytes):
    """ Generate a fernet-compatible key from the bytes """
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"", iterations=100000,)
    key_fernet = base64.urlsafe_b64encode(kdf.derive(key_bytes))
    return key_fernet

def encrypt_data(key_str:str, data: str, encoding:str="utf-8") -> str:
    """ Given a key and data, encrypt it and return the encrypted data. """
    key = key_encode(key_str.encode(encoding))

    cipher = Fernet(key)
    encrypted_bytes = cipher.encrypt(data.encode())
    encrypted_str = encrypted_bytes.decode(encoding)
    return encrypted_str


def decrypt_data(key_str:str, data: str, encoding:str="utf-8") -> str:
    """ Given a key and data previously encrypted with it, return the decrypted
        data. """
    key = key_encode(key_str.encode(encoding))

    cipher = Fernet(key)
    decrypted_bytes = cipher.decrypt(data.encode(encoding))
    decrypted_str = decrypted_bytes.decode(encoding)
    return  decrypted_str


def parse_request(req) -> PreparedRequest|None:
    """ Parses the request into a Prepared Request object. Returns
        None if the request cannot be parsed or if fields are missing. """
    prepared_request = PreparedRequest()
    try:
        prepared_request.action = req["action"]
        prepared_request.key = json.dumps(["key"])
        prepared_request.data = req["data"]
    except KeyError as e:
        print(f"KeyError during parse of request: {str(e)}")
        return None

    return prepared_request


def process_request(prepared_request: PreparedRequest, rep: Response) -> Response|None:
    """ Processes the request and stores the resulting status and data in
        rep. """
    action = prepared_request.action
    key = prepared_request.key
    data = json.dumps(prepared_request.data)

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