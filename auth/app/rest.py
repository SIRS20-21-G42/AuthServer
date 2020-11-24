import model
import globalized

from listener_utils import sign_to_b64

import time

from flask import Flask, jsonify

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


def launch():
    app.run(host='0.0.0.0',
            debug=True,
            use_reloader=False,
            ssl_context=('./AUTH.cert', './AUTH.key'))
