from model import connect, init
from listener import listen
from rest import launch
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import time


def main():
    # DB stuff
    connect()
    init()

    # Load private key
    private_key = None
    with open('./testserver.key', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(),
                                                         password=None)

    # Load CA cert
    CA_cert = None
    with open('./CA.cert', 'rb') as f:
        CA_cert = x509.load_pem_x509_certificate(f.read())

    # TCP stuff
    listener = listen()

    # REST stuff
    launch()


if __name__ == '__main__':
    time.sleep(20)  # Wait for DB to connect
    main()
