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
        global connection
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
            secret BLOB NOT NULL,
            cert BLOB NOT NULL,
            PRIMARY KEY (username)
        );
        ''')
        connection.commit()
        cur.close()
        print('Initialized MySQL database')
    except Error as e:
        print(e)


def get_user(username):
    try:
        global connection
        cur = connection.cursor()

        q = "SELECT * FROM Users WHERE username = %s"
        values = (username,)
        cur.execute(q, values)
        data = cur.fetchall()
        cur.close()
        return data
    except Error as e:
        print(e)
        return None


def add_user(username, secret, cert_bytes):
    try:
        global connection
        cur = connection.cursor()

        q = "INSERT INTO Users (username, secret, cert) VALUES (%s, %s, %s)"
        values = (username, secret, cert_bytes)
        cur.execute(q, values)
        connection.commit()
        cur.close()
        print("Added user", username)
        return True
    except Error as e:
        print(e)
        return False
