import globalized
from model import connect, init
from listener import listen
from rest import launch

import time


def main():
    # DB stuff
    connect()
    init()

    globalized.init()

    # TCP stuff
    listener = listen()

    # REST stuff
    launch()


if __name__ == '__main__':
    time.sleep(20)  # Wait for DB to connect
    main()
