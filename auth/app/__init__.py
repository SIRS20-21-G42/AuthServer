from model import connect, init
import time


def main():
    connect()
    init()


if __name__ == '__main__':
    time.sleep(20)  # Wait for DB to connect
    main()
