import base64
import json
import time
import requests

from cryptography import x509
from cryptography.hazmat.primitives import asymmetric, hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

import model


def part1_parts(part1_b64):
    part1_bytes = base64.b64decode(part1_b64)
    try:
        from globalized import private_key
        part1_dec = private_key.decrypt(part1_bytes,
                                        asymmetric.padding.PKCS1v15())
    except ValueError as e:
        print(f"decryption of part1 failed: {e}")
        return None, '{"error": "decryption of part1 failed"}'
    # Check structure of part1
    part1 = json.loads(part1_dec)
    expected = ["secretKey", "ts", "username"]
    real = sorted(list(part1.keys()))
    if expected != real:
        raise RuntimeError("Invalid part1 structure")

    ts = str(part1["ts"])
    secret_key_b64 = part1["secretKey"]
    secret_key = None
    try:
        secret_key = base64.b64decode(secret_key_b64)
    except Exception as e:
        print(f"invalid base64 for secretKey: {e}")
        return None, '{"error": "base64 of secretKey was invalid"}'
    if len(secret_key) != 32:  # 256//8
        print("wrong size for secretKey")
        return None, '{"error": "wrong size for secretKey, 256 bits"}'

    username = part1["username"]
    return (ts, username, secret_key, secret_key_b64), None


def iv_from_b64(iv_b64):
    try:
        iv = base64.b64decode(iv_b64)
    except Exception as e:
        print(f"invalid base64 for IV: {e}")
        return None, '{"error": "base64 of IV was invalid"}'
    if len(iv) != 16:  # 128//8
        print("wrong size for IV")
        return None, '{"error": "wrong size for IV, 128 bits"}'
    return iv, None


def decrypt_aes_b64_to_dic(content_b64, key, iv):
    content_bytes = base64.b64decode(content_b64)
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(content_bytes) + decryptor.finalize()

        # remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        content_json = unpadder.update(decrypted) + unpadder.finalize()
    except ValueError as e:
        print(f"decryption of AES failed: {e}")
        return None, '{"error": "decryption of AES failed"}'
    return json.loads(content_json), None


def part2_parts(part2_b64, secret_key, iv):
    part2, error = decrypt_aes_b64_to_dic(part2_b64, secret_key, iv)
    if error:
        return None, error

    expected = ["certificate", "signature"]
    real = sorted(list(part2.keys()))
    if expected != real:
        raise RuntimeError("Invalid part2 structure")

    der_cert_b64 = part2["certificate"]
    der_cert = None
    try:
        der_cert = base64.b64decode(der_cert_b64)
    except Exception as e:
        print(f"invalid base64 for certificate: {e}")
        return None, '{"error": "base64 of certificate was invalid"}'

    certificate = None
    try:
        certificate = x509.load_der_x509_certificate(der_cert)
    except Exception as e:
        print(f"Error with loading cert: {e}")
        return None, '{"error": "Could not load cert"}'

    from globalized import CA_cert
    CA_pub_key = CA_cert.public_key()
    try:
        CA_pub_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                asymmetric.padding.PKCS1v15(),
                certificate.signature_hash_algorithm
        )
    except Exception:
        print("Invalid certificate signature")
        return None, '{"error": "Invalid signature in cert"}'

    signature_b64 = part2["signature"]
    signature = None
    try:
        signature = base64.b64decode(signature_b64)
    except Exception as e:
        print(f"invalid base64 for signature: {e}")
        return None, '{"error": "base64 of signature was invalid"}'
    if len(signature) != 256:  # 2048//8
        print("wrong size for signature")
        return None, '{"error": "wrong size for signature, 256 bytes"}'

    return (certificate, signature), None


def aes_encrypt_to_b64(plain, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    # add padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plain) + padder.finalize()
    ciphertxt = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ciphertxt).decode()


def sign_to_b64(plain):
    from globalized import private_key
    signature = private_key.sign(plain,
                                 asymmetric.padding.PKCS1v15(),
                                 hashes.SHA256())
    return base64.b64encode(signature).decode()


def parts_3rd_message(message, secret_key, pub_key):
    # Check structure of message
    expected = ["content", "iv"]
    real = sorted(list(message.keys()))
    if expected != real:
        raise RuntimeError("Invalid message structure")

    # Get iv
    iv_b64 = message["iv"]
    iv, error = iv_from_b64(iv_b64)
    if error:
        return None, error

    # Get content
    content_b64 = message["content"]
    content_dic, error = decrypt_aes_b64_to_dic(content_b64, secret_key, iv)
    if error:
        return None, error

    # Check structure of content
    expected = ["B", "signature", "ts", "username"]
    real = sorted(list(content_dic.keys()))
    if expected != real:
        raise RuntimeError("Invalid content structure")

    B = content_dic["B"]
    signature_b64 = content_dic["signature"]
    signature = None
    try:
        signature = base64.b64decode(signature_b64)
    except Exception as e:
        print(f"invalid base64 for signature: {e}")
        return None, '{"error": "base64 of signature was invalid"}'
    if len(signature) != 256:  # 2048//8
        print("wrong size for signature")
        return None, f'{"error": "wrong size for signature, {len(signature)} bytes"}'
    ts = str(content_dic["ts"])
    username = content_dic["username"]

    # Verify signature
    to_hash = (ts + username + B).encode()
    try:
        pub_key.verify(signature,
                       to_hash,
                       asymmetric.padding.PKCS1v15(),
                       hashes.SHA256())
    except InvalidSignature:
        print("Invalid signature of content")
        return None, '{"error": "Signature of content was invalid"}'

    return (B, username, ts), None


def sha256(secret):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(secret)
    return digest.finalize()


def list_request(first_msg_obj):
    # Check structure of first_msg_obj
    expected = ["list"]
    real = sorted(list(first_msg_obj.keys()))
    if expected != real:
        print("Invalid message structure")
        return None, '{"error": "Invalid message structure"}'

    parts = first_msg_obj["list"]
    # Check structure of parts
    expected = ["content", "iv", "username"]
    real = sorted(list(parts.keys()))
    if expected != real:
        print("Invalid message structure")
        return None, '{"error": "Invalid message structure"}'

    # Get username
    username = parts["username"]
    if type(username) != str:
        print("Username isn't str")
        return None, '''{"error": "Username isn't str"}'''

    # Get user
    user = model.get_user(username)
    if not user:
        print("username not registered")
        return None, '{"error": "username not registered"}'

    _, shared_secret, der_cert, _, _ = user

    certificate = None
    try:
        certificate = x509.load_der_x509_certificate(der_cert)
    except Exception as e:
        print(f"Error with loading cert: {e}")
        return None, '{"error": "Could not load cert"}'

    # Get iv
    iv_b64 = parts["iv"]
    iv, error = iv_from_b64(iv_b64)
    if error:
        return None, error

    secret_key = sha256(shared_secret)
    content_b64 = parts["content"]
    content, error = decrypt_aes_b64_to_dic(content_b64, secret_key, iv)
    if error:
        return None, error

    # check structure of content
    expected = ["signature", "ts", "username"]
    real = sorted(list(content.keys()))
    if expected != real:
        print("Invalid content structure")
        return None, '{"error": "Invalid content structure"}'

    inner_username = content["username"]
    if inner_username != username:
        print("inner username does not match")
        return None, '{"error": "inner username does not match"}'

    ts = content["ts"]
    ts_int = None
    try:
        ts_int = int(ts)
    except ValueError:
        print("timestamp is not int")
        return None, '{"error": "timestamp is not int"}'

    now = int(time.time())
    if not (now - 2*60 < ts_int < now + 1*60):
        print("timestamp out of acceptable range")
        return None, '{"error": "timestamp out of acceptable range"}'

    signature_b64 = content["signature"]
    signature = None
    try:
        signature = base64.b64decode(signature_b64)
    except Exception as e:
        print(f"invalid base64 for signature: {e}")
        return None, '{"error": "base64 of signature was invalid"}'
    if len(signature) != 256:  # 2048//8
        print("wrong size for signature")
        return None, '{"error": "wrong size for signature, 256 bytes"}'

    # Verify signature
    to_sign = (username + ts).encode()
    pub_key = certificate.public_key()
    try:
        pub_key.verify(signature, to_sign, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        print("Invalid signature")
        return None, '{"error": "Signature was invalid"}'

    return (username, ts, secret_key), None


def auth_request(first_msg_obj):
    # Check structure of first_msg_obj
    expected = ["auth"]
    real = sorted(list(first_msg_obj.keys()))
    if expected != real:
        print("Invalid message structure")
        return None, '{"error": "Invalid message structure"}'

    parts = first_msg_obj["auth"]
    # Check structure of parts
    expected = ["content", "iv", "username"]
    real = sorted(list(parts.keys()))
    if expected != real:
        print("Invalid message structure")
        return None, '{"error": "Invalid message structure"}'

    # Get username
    username = parts["username"]
    if type(username) != str:
        print("Username isn't str")
        return None, '''{"error": "Username isn't str"}'''

    # Get user
    user = model.get_user(username)
    if not user:
        print("username not registered")
        return None, '{"error": "username not registered"}'

    _, shared_secret, der_cert, _, _ = user

    certificate = None
    try:
        certificate = x509.load_der_x509_certificate(der_cert)
    except Exception as e:
        print(f"Error with loading cert: {e}")
        return None, '{"error": "Could not load cert"}'

    # Get iv
    iv_b64 = parts["iv"]
    iv, error = iv_from_b64(iv_b64)
    if error:
        return None, error

    secret_key = sha256(shared_secret)
    content_b64 = parts["content"]
    content, error = decrypt_aes_b64_to_dic(content_b64, secret_key, iv)
    if error:
        return None, error

    # check structure of content
    expected = ["hash", "resp", "signature", "ts"]
    real = sorted(list(content.keys()))
    if expected != real:
        print("Invalid content structure")
        return None, '{"error": "Invalid content structure"}'

    ts = content["ts"]
    ts_int = None
    try:
        ts_int = int(ts)
    except ValueError:
        print("timestamp is not int")
        return None, '{"error": "timestamp is not int"}'

    now = int(time.time())
    if not (now - 2*60 < ts_int < now + 1*60):
        print("timestamp out of acceptable range")
        return None, '{"error": "timestamp out of acceptable range"}'

    update_hash = content["hash"]
    if type(update_hash) != str:
        print("hash isn't str")
        return None, '''{"error": "hash isn't str"}'''

    resp = content["resp"]
    signature_b64 = content["signature"]
    signature = None

    try:
        signature = base64.b64decode(signature_b64)
    except Exception as e:
        print(f"invalid base64 for signature: {e}")
        return None, '{"error": "base64 of signature was invalid"}'

    # Verify signature
    to_sign = (ts + resp + update_hash).encode()
    pub_key = certificate.public_key()
    try:
        pub_key.verify(signature,
                       to_sign,
                       asymmetric.padding.PKCS1v15(),
                       hashes.SHA256())
    except InvalidSignature:
        print("Invalid signature")
        return None, '{"error": "Signature was invalid"}'

    return (username, ts, secret_key, update_hash, resp), None


def auth_to_web(username, update_hash, action):
    """
    {
      "username": str,
      "resp": str,
      "hash": str,
      "signature": base64
    }
    """
    to_sign = (username + action + update_hash).encode()
    signed = sign_to_b64(to_sign)

    message = {"username": username,
               "resp": action,
               "hash": update_hash,
               "signature": signed}

    resp = requests.post("https://172.19.0.2:8080/authorize", json=message)

    return resp.status_code == 200
