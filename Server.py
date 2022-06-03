import socket
import threading
from cryptography.hazmat.primitives import serialization as serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import time
import base64
import sqlite3
import sys
from sqlite3 import Error
import pickle

def encrypt_message(message, key1):
    ciphertext = key1.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return ciphertext


def decrypt_message(ciphertext, key1):
    plaintext = key1.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return plaintext


def encrypt_symmetrically(message, cipher):
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(bytes(message, 'utf-8')) + encryptor.finalize()
    return encrypted_message


def decrypt_symmetrically(ciphertext, cipher):
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def send_message_symmetrically(message, socket_choice, cipher_choice, byte_bool):
    if byte_bool == True:
        message = message + bytes(((16 - (len(message) % 16)) * "|"), 'utf-8')
        encryptor = cipher_choice.encryptor()
        encrypted_message = encryptor.update(message) + encryptor.finalize()
        socket_choice.send(encrypted_message)

    else:
        message = message + ((16 - (len(message) % 16)) * "|")
        message = encrypt_symmetrically(message, cipher_choice)
        if type(message) == bytes:
            socket_choice.send(message)
        elif type(message) == str:  # see if we can delete this later??
            socket_choice.send(message.encode('utf-8'))
        else:
            print("Message format error.")


def receive_message_symmetrically(socket_choice, cipher_choice):
    message = socket_choice.recv(2048)
    if type(message) == str:
        message = message.decode('utf-8')
    elif type(message) == bytes:
        pass
    message = decrypt_symmetrically(message, cipher_choice)
    message = message.decode('utf-8')
    return message.rstrip("|")


def create_connection(path):
    try:
        connection = sqlite3.connect(path)
    except Error as e:
        print(f"The error '{e}' occured.")
        sys.exit()
    print("Connection to SQLite DB successful.")
    return connection


# Keys Created(Experiment what what the keys generate from, right now its always the same, Server&Client needs to be
# generated randomly, every time)
my_private_key = rsa.generate_private_key(
    backend=crypto_default_backend(),
    public_exponent=65537,
    key_size=2048)

my_public_key = my_private_key.public_key()

my_public_key_in_bytes = my_public_key.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo)

# Obtains server ip automatically and sets port.
server_ip = socket.gethostbyname(socket.gethostname())
port = 57293
addr = (server_ip, port)

# Starts socket instance.
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(addr)

# Sets path to DB file. Later update to search local folder for .db file auto-magically.
sql_path = r'C:\Users\ZqyBiWKQEL\PycharmProjects\P2PServerAndClient\P2PServer.db'

# Sets dictionary for active client management.
active_client_dict = {}

def client_connection(connection1, ip_address):
    # Sets global variable for active_client_dict.
    global active_client_dict

    # If ip address is in list, then the client will be asking for updated client list.
    if ip_address[0] in active_client_dict:
        print(f"Connection from: {ip_address} | Reconnecting for update.")
        pickled_active_client_dict = pickle.dumps(active_client_dict)
        send_message_symmetrically(pickled_active_client_dict, connection1, active_client_dict[ip_address[0]][0], True)
        print(f"{ip_address} | sent active list update: {pickled_active_client_dict} | Size: {sys.getsizeof(pickled_active_client_dict)}")

    # If ip address is not in list, server sends server's public key for secure communication.
    elif ip_address[0] not in active_client_dict:
        print(f"Connection from: {connection1} | New Connection.")
        connection1.send(my_public_key_in_bytes)
        print(f"{ip_address} | Sent public key in bytes.")
        time.sleep(.4)

        # Receives symmetric key information. Less intensive for simpler communication.
        symmetric_client_cipher_key = decrypt_message(connection1.recv(4096), my_private_key)
        print(f"{ip_address} | Decrypted client symmetric key.")
        time.sleep(.5)
        symmetric_client_cipher_iv = decrypt_message(connection1.recv(4096), my_private_key)
        print(f"{ip_address} | Decrypted client symmetric iv.")

        # Forms symmetric key object.
        symmetric_client_cipher = Cipher(algorithms.AES(symmetric_client_cipher_key), modes.CBC(symmetric_client_cipher_iv))
        print(f"{ip_address} | Created symmetric client cipher.")

        # Sends test string to ensure encryption. Consider removing this later and catching error with try().
        server_init_string = "This is a test string from the server to ensure the symmetric encryption method works."
        send_message_symmetrically(server_init_string, connection1, symmetric_client_cipher, False)
        print(f"{ip_address} | Sent test string to client.")

        # Login loop for resubmits. Consider adding counter and a blocked IP list to avoid brute force.
        while True:
            # Receives login string.
            login_request_string = receive_message_symmetrically(connection1, symmetric_client_cipher)
            print(f"{ip_address} | Login request received: {login_request_string}")

            # Splits login string into list.
            client_credentials = login_request_string.split(" ")
            print(f"{ip_address} | List client_credentials: {client_credentials}")

            # SQL injection check here: (think about client side too)


            # Hashing setup and for loop to hash only username and password.
            hashed_credentials_list = []
            salt = b''
            for item, count in zip(client_credentials, range(2)):
                item_bytes = bytearray(item, 'utf-8')
                kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=2 ** 14,
                    r=8,
                    p=1,
                )
                hashed_credentials_list.append(base64.urlsafe_b64encode(kdf.derive(item_bytes)))

            # For testing purposes only, check the other prints as well.
            print(f"{ip_address} | List hashed_credentials_list: {hashed_credentials_list}")

            # Creates sql instance and object within thread.
            sql_connection = create_connection(sql_path)
            cursor = sql_connection.cursor()

            # Decodes username and password for SQL server.
            username_hash_plaintext = (hashed_credentials_list[0].decode('utf-8'))
            password_hash_plaintext = (hashed_credentials_list[1].decode('utf-8'))

            print(f"{ip_address} | Username to be queried: {username_hash_plaintext}")

            # Returns SQL data entry in list/tuple.
            cursor.execute(f"SELECT * FROM users WHERE username = (?)", [username_hash_plaintext])
            data = cursor.fetchall()

            # If username is not found, data will be 0.
            if len(data) == 0:
                print(f"{ip_address} | There is no username: {username_hash_plaintext}")
                send_message_symmetrically("Failed!", connection1, symmetric_client_cipher, False)
            # If username is found, data list index is checked against password provided.
            elif data[0][1] == password_hash_plaintext:
                print(f"{ip_address} | Password accepted!")
                send_message_symmetrically("Successful!", connection1, symmetric_client_cipher, False)
                # Need to receive their public key for other clients as well.
                client_public_key = serialization.load_pem_public_key(connection1.recv(4096))
                client_public_key_in_bytes = client_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
                # IP address is saved with cipher, public rsa, and nickname for continued communication and updating client lists.
                ip_cipher_nickname_entry = {ip_address[0]: (symmetric_client_cipher, client_public_key_in_bytes, client_credentials[2])}
                active_client_dict.update(ip_cipher_nickname_entry)
                break
            # If supplied password doesnt match, returns failed!
            elif data[0][1] != password_hash_plaintext:
                print(f"{ip_address} | Password rejected!")
                send_message_symmetrically("Failed!", connection1, symmetric_client_cipher, False)
            # Catch all error check.
            else:
                print(f"{ip_address} | Unknown login error!")
                send_message_symmetrically("Unknown Error!", connection1, symmetric_client_cipher, False)


# Keeps track of active clients.
def client_active_check():
    # Waits 10 seconds and checks every key, IP, in dictionary.
    time.sleep(10)
    global active_client_dict
    while True:
        remove_list = []
        print(f"Active Clients: ")
        for key in active_client_dict:
            client_public_RSA_key = serialization.load_pem_public_key(active_client_dict[key][1])
            active_check_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                active_check_socket.connect((key, 57294))
            except:
                print(f"{key} | {active_client_dict[key][2]} | Dead")
                remove_list.append(key)
                continue
            active_check_socket.send(encrypt_message(b"Are you there?", client_public_RSA_key))
            time.sleep(.2)
            # Results decides if the IP is to be removed from active client dict and prints result in terminal.
            if decrypt_message(active_check_socket.recv(4096), my_private_key).decode('utf-8') == "I'm Alive!":
                print(f"{key} | {active_client_dict[key][2]} | Alive")
            else:
                print(f"{key} | {active_client_dict[key][2]} | Dead")
                remove_list.append(key)
            active_check_socket.close()
        for item in remove_list:
            active_client_dict.pop(item)
        time.sleep(15)


# Creates instance of threading and tracks alive clients.
client_active_check_thread = threading.Thread(target=client_active_check)
client_active_check_thread.start()

# Starts server.
print(f"~ Staring Server ~ \n{server_ip} : {port}")

# Starts server by listening for new connections.
server_socket.listen()
print(f"~ Staring Server ~ \n{server_ip} : {port}")
while True:
    # Continuously accepts new connections and starts new thread for every instance of accept().
    connection, ip = server_socket.accept()
    # Passes connection and ip into function.
    thread = threading.Thread(target=client_connection, args=(connection, ip))
    thread.start()
    print(f"Connection count: {threading.active_count() - 1}")

# Reminder implement count to avoid brute force attack.
