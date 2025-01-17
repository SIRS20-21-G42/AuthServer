from cryptography import x509
from cryptography.hazmat.primitives import serialization


def init(debug=True):
    # Load private key
    global private_key
    with open('./AUTH.key', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(),
                                                         password=None)

    # Load CA cert
    global CA_cert
    with open('./CA.cert', 'rb') as f:
        CA_cert = x509.load_pem_x509_certificate(f.read())

    # Load FaceFive cert
    global FaceFive_cert
    with open('./FaceFive.cert', 'rb') as f:
        FaceFive_cert = x509.load_pem_x509_certificate(f.read())

    # DEBUG?
    global DEBUG
    DEBUG = debug


def debug(text):
    global DEBUG
    if DEBUG:
        print("debug:", text)
