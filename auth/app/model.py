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
            last_code CHAR(6) NOT NULL,
            last_ts INT,
            PRIMARY KEY (username)
        );
        ''')

        cur.execute('''CREATE TABLE Authorizations (
            username VARCHAR(20) BINARY NOT NULL,
            hash VARCHAR(64),
            ts INT,
            PRIMARY KEY (username, hash),
            FOREIGN KEY (username) REFERENCES Users(username)
        );
        ''')

        connection.commit()
        cur.close()
        print('Initialized MySQL database')
    except Error as e:
        print(e)


def add_user(username, secret, cert_bytes):
    try:
        global connection
        cur = connection.cursor()

        q = "INSERT INTO Users (username, secret, cert, last_code, last_ts) "
        q += "VALUES (%s, %s, %s, 'nonono', 0)"
        values = (username, secret, cert_bytes)
        cur.execute(q, values)
        connection.commit()
        cur.close()
        print("Added user", username)
        return True
    except Error as e:
        print(e)
        return False


def get_user(username):
    try:
        global connection
        cur = connection.cursor()

        q = "SELECT * FROM Users WHERE username = %s"
        values = (username,)
        cur.execute(q, values)
        data = cur.fetchone()
        cur.close()
        return data
    except Error as e:
        print(e)
        return None


def get_user_secret(username):
    try:
        global connection
        cur = connection.cursor()

        q = "SELECT secret FROM Users WHERE username = %s"
        values = (username,)
        cur.execute(q, values)
        data = cur.fetchone()
        cur.close()
        return data[0]
    except Error as e:
        print(e)
        return None


def get_user_otp(username):
    try:
        global connection
        cur = connection.cursor()

        q = "SELECT last_code, last_ts FROM Users WHERE username = %s"
        values = (username,)
        cur.execute(q, values)
        data = cur.fetchone()
        cur.close()
        return data
    except Error as e:
        print(e)
        return None


def store_user_otp(username, totp, ts):
    try:
        global connection
        cur = connection.cursor()

        q = "UPDATE Users SET last_code = %s, last_ts=%s "
        q += "WHERE username = %s;"
        values = (totp, ts, username)
        cur.execute(q, values)
        connection.commit()
        cur.close()
        return True
    except Error as e:
        print(e)
        return False


def store_auth(username, update_hash, ts):
    try:
        global connection
        cur = connection.cursor()

        q = "INSERT INTO Authorizations (username, hash, ts) "
        q += "VALUES (%s, %s, %s)"
        values = (username, update_hash, ts)
        cur.execute(q, values)
        connection.commit()
        cur.close()
        print("Added authorization for user", username)
        return True
    except Error as e:
        print(e)
        return False


def get_authorizations(username):
    try:
        global connection
        cur = connection.cursor()

        q = "SELECT hash, ts FROM Authorizations WHERE username = %s;"
        values = (username,)
        cur.execute(q, values)
        data = cur.fetchall()
        cur.close()
        return data
    except Error as e:
        print(e)
        return False


def check_authorization(username, update_hash):
    try:
        global connection
        cur = connection.cursor()

        q = "SELECT hash FROM Authorizations "
        q += "WHERE username = %s AND hash = %s;"
        values = (username, update_hash)
        cur.execute(q, values)
        data = cur.fetchone()
        cur.close()
        return data is not None
    except Error as e:
        print(e)
        return False


def remove_authorization(username, update_hash):
    try:
        global connection
        cur = connection.cursor()

        q = "SELECT hash FROM Authorizations "
        q += "WHERE username = %s AND hash = %s;"
        values = (username, update_hash)
        cur.execute(q, values)
        data = cur.fetchone()
        if data is None:
            return False

        q = "DELETE FROM Authorizations "
        q += "WHERE username = %s AND hash = %s;"
        cur.execute(q, values)
        connection.commit()
        cur.close()
        return True
    except Error as e:
        print(e)
        return False
