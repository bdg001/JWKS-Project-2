from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

hostName = "localhost"
serverPort = 8080

# Initialize SQLite database
db_connection = sqlite3.connect('C:/Users/Blake\Desktop/JWKS_Part_2/totally_not_my_privateKeys.db')
db_cursor = db_connection.cursor()

# Create a table to store keys
db_cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')

db_connection.commit()

# Function to insert a key into the database
def insert_key(key_data, exp):
    db_cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (key_data, exp))
    db_connection.commit()

# Function to retrieve a key from the database by kid
def get_key(kid):
    db_cursor.execute('SELECT key FROM keys WHERE kid = ?', (kid,))
    result = db_cursor.fetchone()
    return result[0] if result else None

# Function to retrieve exp by kid
def get_exp(kid):
    db_cursor.execute('SELECT exp FROM keys WHERE kid = ?', (kid,))
    result = db_cursor.fetchone()
    return result[0] if result else None

# Function to get first unexpired key
def get_first_unexpired_key():
    current_time = datetime.datetime.utcnow()
    db_cursor.execute('SELECT key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1', (current_time,))
    result = db_cursor.fetchone()
    return result[0] if result else None

# Function to get first expired key
def get_first_expired_key():
    current_time = datetime.datetime.utcnow()
    db_cursor.execute('SELECT key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1', (current_time,))
    result = db_cursor.fetchone()
    return result[0] if result else None


private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

insert_key(pem, datetime.datetime.utcnow() + datetime.timedelta(hours=1))
insert_key(expired_pem, datetime.datetime.utcnow() - datetime.timedelta(hours=1))

private_key = None
expired_key = None
pem = None
expired_pem = None

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            encoded_jwt = jwt.encode(token_payload, get_first_expired_key(), algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            pem = get_first_unexpired_key()
            private_key = serialization.load_pem_private_key(
                pem,
                password = None,
            )

            numbers = private_key.private_numbers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            pem = None
            private_key = None
            numbers = None
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    db_connection.close()
    webServer.server_close()
    