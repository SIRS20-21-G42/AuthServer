from flask import Flask, request, jsonify
from json import loads

app = Flask(__name__)

app.config['SECRET_KEY'] = '\x83\xe1\xba%j\x0b\xe5Q\xdeiG\xde\\\xb1\x94\xe4\x0e\x1dk\x99\x1a\xda\xe8x'


@app.route('/authenticate/<user>/<totp>', methods=['GET'])
def authenticate(user, totp):
    return jsonify({'resp': 'hello'+user, 'totp': totp})


def launch():
    app.run(host='0.0.0.0',
            debug=True,
            use_reloader=False,
            ssl_context=('./AUTH.cert', './AUTH.key'))
