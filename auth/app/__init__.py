from model import connect, init
from listener import listen
import time


def main():
    # DB stuff
    connect()
    init()

    # TCP stuff
    listener = listen()


if __name__ == '__main__':
    time.sleep(20)  # Wait for DB to connect
    main()
