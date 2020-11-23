import base64
import json
import os
import socket
import time
import threading

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.exceptions import InvalidSignature

import globalized

from listener_utils import part1_parts, iv_from_b64, part2_parts
from listener_utils import sign_to_b64, parts_3rd_message, aes_encrypt_to_b64
from model import get_user, add_user


def listen():
    """
    Start listening in the background
    """
    listener = threading.Thread(target=listen_forever, args=())
    listener.start()
    return listener


TCP_IP = '0.0.0.0'
TCP_PORT = 1337
MSGLEN = 8192


def listen_forever():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((TCP_IP, TCP_PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        handler = threading.Thread(target=handle_connection, args=(conn,))
        handler.start()


def handle_connection(conn):
    try:
        msg_obj = get_message(conn)

        if "reg" in msg_obj:
            registration(msg_obj, conn)
        elif "list" in msg_obj:
            list_auth(msg_obj, conn)
        elif "auth" in msg_obj:
            auth(msg_obj, conn)
        elif "location" in msg_obj:
            location(msg_obj, conn)
        else:
            print("Not a valid starter")
            put_message(conn, '{"error": "Not a valid starter"}')

        conn.close()
    except socket.error as e:
        print("There was an error:", e)
    except json.JSONDecodeError as e:
        print("There was an error with the message:", e)
    except RuntimeError as e:
        print("There was an error:", e)
    except Exception as e:
        print("There was an exception:", e)
    finally:
        if not conn._closed:
            conn.close()


def get_message(conn):
    """
    All messages are valid JSON ending with `\n`
    """
    recvd = b""
    bytes_recvd = 0
    while b"\n" not in recvd and bytes_recvd < MSGLEN:
        chunk = conn.recv(min(MSGLEN-bytes_recvd, MSGLEN))
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        recvd += chunk
        bytes_recvd += len(chunk)
    if b"\n" not in recvd:
        raise RuntimeError("no \\n in message")

    globalized.debug(f"Received: {recvd}")
    return json.loads(recvd.strip())


def put_message(conn, msg):
    globalized.debug(f"Sending: {msg}")
    msg_bytes = msg.encode()
    bytes_sent = 0
    while bytes_sent < len(msg_bytes):
        sent = conn.send(msg_bytes[bytes_sent:])
        if sent == 0:
            raise RuntimeError("socket connection broken")
        bytes_sent += sent


def registration(first_msg_obj, conn):
    # Check structure of first_msg_obj
    expected = ["reg"]
    real = sorted(list(first_msg_obj.keys()))
    if expected != real:
        print("Invalid message structure")
        put_message(conn, '{"error": "Invalid message structure"}')
        return

    parted_obj = first_msg_obj["reg"]
    # Check structure of parted_obj
    expected = ["iv", "part1", "part2"]
    real = sorted(list(parted_obj.keys()))
    if expected != real:
        print("Invalid message structure")
        put_message(conn, '{"error": "Invalid message structure"}')
        return

    # Decrypt part1
    globalized.debug("about to decrypt part1")
    part1_b64 = parted_obj["part1"]
    tup, error = part1_parts(part1_b64)
    if error:
        put_message(conn, error)
        return
    ts, username, secret_key, secret_key_b64 = tup
    ts_int = None
    try:
        ts_int = int(ts)
    except ValueError:
        print("timestamp is not int")
        put_message(conn, '{"error": "timestamp is not int"}')
        return

    globalized.debug("about to check time and username")
    now = int(time.time())
    if not (now - 2*60 < ts_int < now + 1*60):
        print("timestamp out of acceptable range")
        put_message(conn, '{"error": "timestamp out of acceptable range"}')
        return

    user = get_user(username)
    if user:
        print("username already exists")
        put_message(conn, '{"error": "username already exists"}')
        return

    # Get iv
    iv_b64 = parted_obj["iv"]
    iv, error = iv_from_b64(iv_b64)
    if error:
        put_message(conn, error)
        return

    # Decrypt part2
    globalized.debug("about to decrypt part2")
    part2_b64 = parted_obj["part2"]
    tup, error = part2_parts(part2_b64, secret_key, iv)
    if error:
        put_message(conn, error)
        return

    certificate, signature = tup

    # Verify signature
    to_hash = (ts + username + secret_key_b64).encode()
    pub_key = certificate.public_key()
    try:
        pub_key.verify(signature, to_hash, padding.PKCS1v15(), hashes.SHA256)
    except InvalidSignature:
        print("Invalid signature of part1")
        put_message(conn, '{"error": "Signature of part1 was invalid"}')
        return

    DH_parameters = dh.generate_parameters(5, 2048)
    DH_private = DH_parameters.generate_private_key()
    DH_public = DH_private.public_key()
    A = DH_public.public_numbers().y
    numbers = DH_parameters.parameter_numbers()
    g = numbers.g
    N = numbers.p

    to_sign = (ts + str(g) + str(N) + str(A)).encode()
    signature = sign_to_b64(to_sign)

    content_dic = {"ts": ts, "g": g, "N": N, "A": A, "signature": signature}
    content_bytes = json.dumps(content_dic).encode()
    iv2 = os.urandom(16)
    enc_content_b64 = aes_encrypt_to_b64(content_bytes, secret_key, iv2)

    msg_2_dic = {"content": enc_content_b64, "iv": base64.b64encode(iv2)}
    msg_2 = json.dumps(msg_2_dic) + "\n"
    put_message(conn, msg_2)

    # Receive 3rd message
    message = None
    try:
        message = get_message(conn)
    except Exception as e:
        print(f"problem receiving 3rd message: {e}")
        put_message(conn, '{"error": "invalid 3rd message"}')
        return

    globalized.debug("checking parts of 3rd message")
    parts, error = parts_3rd_message(message, secret_key, pub_key)
    if error:
        put_message(conn, error)
        return

    B, new_username, new_ts = parts
    if new_username != username:
        print("username in 3rd message doesn't match")
        put_message(conn, '''{"error": "username doesn't match"}''')
        return
    if new_ts != ts:
        print("ts in 3rd message doesn't match")
        put_message(conn, '''{"error": "ts doesn't match"}''')
        return

    secret = DH_private.exchange(int(B))

    # Store username, secret and certificate bytes
    res = add_user(username,
                   secret,
                   certificate.public_bytes(serialization.Encoding.DER))

    # Send 4th message
    globalized.debug("preparing 4th message")
    resp = "OK" if res else "NO"
    to_sign = (ts + resp).encode()
    signature = sign_to_b64(to_sign)
    content_dic = {"ts": ts, "resp": resp, "signature": signature}
    content_bytes = json.dumps(content_dic).encode()
    iv4 = os.urandom(16)
    enc_content_b64 = aes_encrypt_to_b64(content_bytes, secret_key, iv4)

    msg_4_dic = {"content": enc_content_b64, "iv": base64.b64encode(iv4)}
    msg_4 = json.dumps(msg_4_dic) + "\n"
    put_message(conn, msg_4)


def list_auth(first_msg_obj, conn):
    pass


def auth(first_msg_obj, conn):
    pass


def location(first_msg_obj, conn):
    pass
