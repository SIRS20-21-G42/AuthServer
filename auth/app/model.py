import mysql.connector
from mysql.connector import Error


connection = None


def connect():
    global connection
    if not connection:
        try:
            connection = mysql.connector.connect(host='db',
                                                 database='authdb',
                                                 user='auth',
                                                 password='authpass'
                                                 )
            if connection.is_connected():
                print('Connected to MySQL database')
        except Error as e:
            print(e)
            exit(1)


def init():
    try:
        cur = connection.cursor()

        cur.execute("SHOW TABLES LIKE 'Users'")
        result = cur.fetchone()
        if result:
            cur.close()
            return

        cur.execute("DROP DATABASE IF EXISTS authdb;")
        cur.execute("CREATE DATABASE authdb;")
        cur.execute("USE authdb;")

        cur.execute('''CREATE TABLE Users (
            username VARCHAR(20) BINARY NOT NULL,
            secret BLOB NOT NULL
        );
        ''')
        connection.commit()
        cur.close()
        print('Initialized MySQL database')
    except Error as e:
        print(e)
