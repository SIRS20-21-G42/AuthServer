from model import connect, init
from listener import listen
from rest import launch
from Crypto.PublicKey import RSA
import time


def main():
    # DB stuff
    connect()
    init()

    # Load private key
    private_key = None
    with open('./testserver.key', 'r') as f:
        private_key = RSA.import_key(f.read())

    # Load public key
    CA_public_key = None
    with open('./CA.cert', 'r') as f:
        CA_public_key = RSA.import_key(f.read())


    # TCP stuff
    listener = listen()

    # REST stuff
    launch()


if __name__ == '__main__':
    time.sleep(20)  # Wait for DB to connect
    main()
