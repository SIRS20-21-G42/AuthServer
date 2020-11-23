import model

from listener_utils import sign_to_b64

import time

from flask import Flask, jsonify

app = Flask(__name__)

app.config['SECRET_KEY'] = '\x83\xe1\xba%j\x0b\xe5Q\xdeiG\xde\\\xb1\x94\xe4\x0e\x1dk\x99\x1a\xda\xe8x'


@app.route('/authenticate/<username>/<totp>', methods=['GET'])
def authenticate(username, totp):
    now = int(time.time())

    user = model.get_user(username)
    if not user:
        status = "??"

    else:
        from cryptography.hazmat.primitives.twofactor.totp import TOTP
        from cryptography.hazmat.primitives.twofactor import InvalidToken
        _, secret, _ = user

        from cryptography.hazmat.primitives.hashes import SHA256
        totp_obj = TOTP(secret, 6, SHA256(), 30)
        try:
            # Checking against current code
            totp_obj.validate(totp.encode(), now)
            status = "OK"
        except InvalidToken:
            try:
                # Checking against previoues code
                before = now - 30
                totp_obj.validate(totp.encode(), before)
                status = "OK"
            except InvalidToken:
                status = "NO"

    body = {"username": username, "ts": str(now), "status": status}

    to_sign = (username + str(now) + status).encode()
    signed = sign_to_b64(to_sign)

    return jsonify({'body': body, 'signature': signed})


def launch():
    app.run(host='0.0.0.0',
            debug=True,
            use_reloader=False,
            ssl_context=('./AUTH.cert', './AUTH.key'))
