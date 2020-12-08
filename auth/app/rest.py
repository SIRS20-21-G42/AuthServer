import model
import globalized

from listener_utils import sign_to_b64

import time
import base64

from flask import Flask, jsonify, request, Response
from werkzeug.exceptions import BadRequest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

app.config['SECRET_KEY'] = '\x83\xe1\xba%j\x0b\xe5Q\xdeiG\xde\\\xb1\x94\xe4\x0e\x1dk\x99\x1a\xda\xe8x'


@app.route('/authenticate/<username>/<totp>', methods=['GET'])
def authenticate(username, totp):
    def auth_helper():
        def auth_check(ts):
            try:
                totp_obj.verify(totp.encode(), ts)
                tup = model.get_user_otp(username)
                if not tup:
                    globalized.debug("Failed to get tup")
                    return False
                last_totp, last_ts = tup
                if last_totp == totp and ts - last_ts < 30:
                    globalized.debug("otp already used")
                    return False
            except InvalidToken:
                globalized.debug("Invalid token")
                return False
            # If it fails to store we report failure
            globalized.debug("success, going to store totp and ts")
            return model.store_user_otp(username, totp, ts)

        secret = model.get_user_secret(username)
        if not secret:
            # Unknown user
            globalized.debug(f"Unkown user: {username}")
            return "??"

        from cryptography.hazmat.primitives.twofactor.totp import TOTP
        from cryptography.hazmat.primitives.twofactor import InvalidToken

        from cryptography.hazmat.primitives.hashes import SHA256
        totp_obj = TOTP(secret, 6, SHA256(), 30)
        if auth_check(now) or auth_check(now-30):
            return "OK"
        else:
            return "NO"

    now = int(time.time())
    status = auth_helper()

    body = {"username": username, "ts": str(now), "status": status}

    to_sign = (username + str(now) + status).encode()
    signed = sign_to_b64(to_sign)

    return jsonify({'body': body, 'signature': signed})


@app.route('/authorize', methods=['POST'])
def authorize():
    body = request.get_json()
    if not body:
        raise BadRequest("Missing JSON body")
    expected = ["hash", "signature", "ts", "username"]
    real = sorted(list(body.keys()))
    if expected != real:
        raise BadRequest("Wrong JSON fields")

    username = body["username"]
    update_hash = body["hash"]
    ts = body["ts"]
    ts_int = None
    try:
        ts_int = int(ts)
    except ValueError:
        raise BadRequest("ts can't be converted to int")

    signature_b64 = body["signature"]
    signature = None
    try:
        signature = base64.b64decode(signature_b64)
    except Exception:
        raise BadRequest("Invalid base64 for signature")

    # Verify signature
    to_hash = (username + str(ts) + update_hash).encode()
    pub_key = globalized.FaceFive_cert.public_key()
    try:
        pub_key.verify(signature, to_hash, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise BadRequest("Invalid signature of request")

    user = model.get_user(username)
    if not user:
        globalized.debug(f"posting authorization for unkown user: {username}")
        raise BadRequest("Unknown user")

    success = model.store_auth(username, update_hash, ts_int)
    if success:
        return Response("", status=201)
    else:
        return Response("", status=500)


@app.route('/location/<username>', methods=['GET'])
def location(username):
    def location_helper():
        safe_ts = model.get_safe_ts(username)
        if not safe_ts:
            # Unknown user
            globalized.debug(f"Unkown user: {username}")
            return "??"

        return "OK" if now < safe_ts + 5 * 60 else "NO"

    now = int(time.time())
    ts = str(now)

    status = location_helper()

    to_sign = (username + status + ts).encode()

    return jsonify({
              "username": username,
              "status": status,
              "ts": ts,
              "signature": sign_to_b64(to_sign)
            })


def launch():
    app.run(host='0.0.0.0',
            debug=True,
            use_reloader=False,
            ssl_context=('./AUTH.cert', './AUTH.key'))
