import os
import socket
import sys
from cryptography.hazmat.primitives import serialization as serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import time
import tkinter
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pickle
import threading

# Keys Created.
my_private_key = rsa.generate_private_key(
    backend=crypto_default_backend(),
    public_exponent=65537,
    key_size=2048)

my_public_key = my_private_key.public_key()

my_public_key_in_bytes = my_public_key.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo)

client_test_string = "Vi veri veniversum vivus vici."


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


def encrypt_asymmetrically(message, cipher):
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(bytes(message, 'utf-8')) + encryptor.finalize()
    return encrypted_message


def send_message_symmetrically(message, socket_choice, cipher_choice):
    message = message + ((16 - (len(message) % 16)) * "|")
    message = encrypt_asymmetrically(message, cipher_choice)
    if type(message) == bytes:
        socket_choice.send(message)
    elif type(message) == str:
        socket_choice.send(message.encode('utf-8'))
    else:
        print("Message type error.")


def decrypt_symmetrically(ciphertext, cipher):
    decryptor = cipher.decryptor()
    print(len(ciphertext))
    return decryptor.update(ciphertext) + decryptor.finalize()


def receive_message_symmetrically(socket_choice, cipher_choice, byte_bool):
    message = socket_choice.recv(2048)
    if byte_bool:
        message = decrypt_symmetrically(message, cipher_choice)
        message = message.rstrip(b"|")
        return message
    else:
        if type(message) == str:
            message = message.decode('utf-8')
        elif type(message) == bytes:
            pass
        message = decrypt_symmetrically(message, cipher_choice)
        message = message.decode('utf-8')
        return message.rstrip("|")


def create_cipher():
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    return cipher, key, iv


def listening_socket():
    global active_client_dict
    # This static assignment is for testing purposes only. Will need to sense OS, and do a custom sys command for IP
    # for Linux vs Windows.
    # host_ip = socket.gethostbyname(socket.gethostname())
    host_ip = "192.168.5.102"
    listening_port = 57294

    addr = (host_ip, listening_port)

    # Sets up socket instance for chat that are received.
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiver_socket.bind(addr)
    receiver_socket.listen()
    print(f"Listening on {addr}")
    while True:
        # Continuously accepts new connections and starts new thread for every instance of accept().
        connection, ip = receiver_socket.accept()
        print(f"Connection from: {connection} | New Connection.")
        # print(f"Test String | Server ip: {server_ip} & connection ip is: {ip[0]}")
        # Checks to see if that IP is online.
        if ip[0] in active_client_dict.keys():
            # Passes connection and ip into function.
            receiving_thread = threading.Thread(target=client_connection, args=(connection, ip))
            receiving_thread.start()
            print(f"IP from {connection} authenticated.")
            print(f"Initiated connection received from: {connection}")
            print(f"Connection count: {threading.active_count() - 1}")
        # If the server connects, client recognizes ip and knows this is an alive check.
        elif ip[0] == server_ip:
            check_alive_string = decrypt_message(connection.recv(4096), my_private_key)
            if check_alive_string.decode('utf-8') == "Are you there?":
                connection.send(encrypt_message(b"I'm Alive!", server_public_key))
            else:
                print(f"Invalid input received from server. Alive check failed.")
            connection.close()
        # If the connection IP is not in the active dictionary or matching the server ip, then connection is refused.
        else:
            print(f"Connection from {connection} refused. Not authenticated from server.")
            connection.close()


def client_connection(connection, ip):
    global active_client_dict
    global client_test_string
    # Get connecting clients information.
    for key in active_client_dict.keys():
        if ip == key:
            print(f"Found connecting ip in active users: {ip} ")
            client_public_key = serialization.load_pem_public_key((active_client_dict[key][1]))
            client_nickname = active_client_dict[key][1]
        else:
            print(f"Error: client_connection function failed to find ip in active_client_dict. IP: {ip}")
            return

    # Receive their public key encrypted by mine.
    received_public_key = decrypt_message(connection.recv(4096), my_private_key)
    if received_public_key != client_public_key:
        print(f"Error: client_connection() key provided is incorrect. IP: {ip}")
        return
    else:
        print(f"Key authentication successful. IP: {ip}")

    # Sets up symmetrical encryption with key and IV to create a cipher.
    time.sleep(.2)
    client_cipher_key = decrypt_message(connection.recv(4096), my_private_key)
    time.sleep(.2)
    client_cipher_iv = decrypt_message(connection.recv(4096), my_private_key)
    c2c_cipher = Cipher(algorithms.AES(client_cipher_key), modes.CBC(client_cipher_iv))

    # Sends test string to server to ensure symmetrical encryption is correct.
    send_message_symmetrically(client_test_string, connection, c2c_cipher)

    time.sleep(.2)

    if receive_message_symmetrically(connection, c2c_cipher, False) == "Failure!":
        print(f"Failed symmetric test. IP: {ip}")
        connection.close()
        return
    elif receive_message_symmetrically(connection, c2c_cipher, False) == "Successful!":
        print(f"Successful symmetric test. IP: {ip}")
    else:
        print(f"Response unknown. IP: {ip}")
        connection.close()
        return

    tkinter_chat(client_nickname, c2c_cipher, connection)

# tkinter instance for each peer to peer session.
def tkinter_chat(peer_name, c2c_cipher, conn):
    chat1 = tkinter.Tk()
    chat1.title(f"Encrypted Chat | {peer_name}")
    chat1.geometry('550x620')
    chat1.configure(background="black")

    send_boolean = True
    def switch_bool():
        global send_boolean
        send_boolean = not send_boolean
    messages = []

    l1 = tkinter.Label(chat1, text=peer_name, bg="black", fg="white", font="none 12 bold", width='55')
    l1.grid(row=0, column=0)

    l2 = tkinter.Label(chat1, text="", bg="gray", fg="white", font="none 12 bold", width='55', height='28')
    l2.grid(row=1, column=0)

    e1 = tkinter.Entry(chat1, text="", bg="gray", fg="white", font="none 12 bold", width='51')
    e1.grid(row=2, column=0, sticky="w")

    b2 = tkinter.Button(chat1, text="Send", width=10, command=(lambda: switch_bool()))
    b2.grid(row=2, column=0, padx=10, pady=5, sticky="e")

    # Consider taking this code out of the function and passing it alone. How do I put logic/execution
    # inside tkinter mainloop()..... https://pythonguides.com/python-tkinter-mainloop/

    def messaging_loop():
        global send_boolean
        if send_boolean == True:
            incoming_chat_message = receive_message_symmetrically(conn, c2c_cipher, False)
            if incoming_chat_message != "":
                incoming_chat_time = time.strftime('%l:%M%p %z on %b %d, %Y')
                messages.append(f"{incoming_chat_message} | {incoming_chat_time}")
                while len(messages) > 10:
                    del messages[0]
                # Update message string from list here
            else:
                time.sleep(.1)
        else:
            message_to_send = e1.get()
            if message_to_send != "":
                send_message_symmetrically(message_to_send, conn, c2c_cipher)
                messages.append(f"{message_to_send} | {time.strftime('%l:%M%p %z on %b %d, %Y')}")
                while len(messages) > 10:
                    del messages[0]
                # Update message string from list here
            send_boolean = True

    messaging_loop()
    chat1.mainloop()

# Input for server connection.
server_ip = input("What is the server IP address? ")
server_port = 57293

# Begin socket instance and tries to connect to server for the first time.
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    server_socket.connect((server_ip, server_port))
except:
    print("Error while binding connection to server.")
    sys.exit()
print(f"Connected to server: {server_ip}")

# IP address are set.
host_name = socket.gethostname()
ip_address = socket.gethostbyname(host_name)

# Receiving server public RSA key.
try:
    server_public_key = serialization.load_pem_public_key(server_socket.recv(4096))
except:
    print("Server thought you were still connected. Check server alive list.")
    sys.exit()

# Creating symmetric cipher and retains/sends key/iv to send to server.
# Create a function/gui for this later, it's also used in get_entry()
# Combine these in list and pickle them to the server.
server_cipher, server_cipher_key, server_cipher_iv = create_cipher()
encrypted_server_cipher_key = encrypt_message(server_cipher_key, server_public_key)
server_socket.send(encrypted_server_cipher_key)
time.sleep(.5)
encrypted_server_cipher_iv = encrypt_message(server_cipher_iv, server_public_key)
server_socket.send(encrypted_server_cipher_iv)

time.sleep(.5)

# Reads socket data and tests symmetric encryption method for standard phrase.
server_initialization_string = "This is a test string from the server to ensure the symmetric encryption is accurate."
server_initialization_string_test = receive_message_symmetrically(server_socket, server_cipher, False)

if server_initialization_string_test == server_initialization_string:
    print("Secure connection completed.")
else:
    print("Symmetric encryption failed.")
    sys.exit()

# Gets input for username, password and nickname.
while True:
    username1 = input("Username: ").strip(" ")
    password1 = input("Password: ").strip(" ")
    nickname = input("Nickname: ").strip(" ")
    # For nickname, constraints are implemented because this is the only parameter the user can freely choose.
    if len(username1) > 50 or len(password1) > 50 or len(nickname) > 20 or len(nickname) < 3 or " " in nickname:
        input("Username, Password, or Nickname is too long or too short. Remove spaces from Nickname.")
    else:
        # Login Attempt with formatted username, password, and nickname string.
        login_string = username1 + " " + password1 + " " + nickname
        send_message_symmetrically(login_string, server_socket, server_cipher)

        time.sleep(.5)

        # Server responds with login result.
        login_result = receive_message_symmetrically(server_socket, server_cipher, False)
        if login_result == "Successful!":
            print("Login Successful!")
            # When successful, client sends its public key and breaks out of login loop.
            server_socket.send(my_public_key_in_bytes)
            server_socket.close()
            break
        elif login_result == "Failed!":
            print("Login failed!")
        elif login_result == "Unknown Error!":
            print("Login failed!")
            sys.exit()
        else:
            input("Unexpected server response: " + login_result)
            server_socket.close()
            sys.exit()

# Listening port thread for alive checks from server.
active_client_dict = {}
listening_socket_thread = threading.Thread(target=listening_socket)
listening_socket_thread.start()

# Sets up tkinter UI for updating user list and starting new chats.
def tkinter_main():

    # Variable to insert = (server_ip, server_port, server_cipher, l2)
    def update_active_users():
        global active_client_dict
        # Creates separate instance of socket for connect. # Replace with try ping().
        server_socket_fun = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_socket_fun.connect((server_ip, server_port))
        except:
            print("Error while binding connection to server during reconnect.")
        print("Reconnected to server for update!")

        pickled_active_client_dict = receive_message_symmetrically(server_socket_fun, server_cipher, True)
        active_client_dict = pickle.loads(pickled_active_client_dict)
        print(f"Updated active_users_dictionary: \n{active_client_dict}")

        active_client_string = ""
        for key in active_client_dict:
            dict_list = active_client_dict.get(key)
            print(dict_list)
            active_client_string += "\n" + dict_list[2]

        # This is to update the seen list in the GUI. May need individual boxes to click.
        l2.configure(text=active_client_string.lstrip("\n"))

        server_socket_fun.close()


    def get_entry():
        global active_client_dict
        # Retrieves input from entry on tkinter GUI.
        sel_user = e1.get()
        if sel_user == "":
            return
        print(f"Selected user: {sel_user}")
        # Loops through values in keys, looking for a match. Could specify [2] for each value instead.
        sel_user_ip = None
        for key in active_client_dict.keys():
            for value in active_client_dict[key]:
                if value == sel_user:
                    # Once user is found, we extract the IP and public key from our dictionary.
                    print(f"The client IP is: {key} for the value is: {value}")
                    sel_user_ip = key
                    sel_user_public_key = serialization.load_pem_public_key((active_client_dict[key][1]))

        # If user is not found, this ends the functions execution.
        if sel_user_ip == None:
            print(f"User not found: {sel_user}")
            return

        # Starts a thread passing IP, the username, and their public key.
        init_thread = threading.Thread(target=init_client_connection, args=(sel_user_ip, sel_user, sel_user_public_key))
        init_thread.start()
        print(f"Connection count: {threading.active_count() - 1}")

    def init_client_connection(ip1, user, client_public_key):
        global client_test_string
        # Set up socket instance
        selected_user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            selected_user_port = 57294
            selected_user_socket.connect((ip1, selected_user_port))
        except:
            print(f"Error while binding connection to client: {user}")
            return

        # Sends my public key encrypted by their public key.
        # Sending bytes, may be an issue? Don't forget "byte_bool" on receiving side.
        # gotta do the different functions here.
        encrypted_initiatior_key = encrypt_message(my_public_key_in_bytes, client_public_key)
        selected_user_socket.send(encrypted_initiatior_key)

        time.sleep(.2)

        # Send these credentials pickled, maybe in touple? touple, pickle, then encrypt
        # Make sure it isn't over the packet size, change on server side, and client to client as well.

        # Creates symmetric cipher for this user.
        c2c_cipher, c2c_cipher_key, c2c_cipher_iv = create_cipher()
        encrypted_symmetric_key = encrypt_message(c2c_cipher_key, client_public_key)
        selected_user_socket.send(encrypted_symmetric_key)
        time.sleep(.2)  # Comment these out later to test necessity.
        encrypted_symmetric_iv = encrypt_message(c2c_cipher_iv, client_public_key)
        selected_user_socket.send(encrypted_symmetric_iv)

        time.sleep(.2)

        # Client authenticates initiator, initiator confirms symmetric communication.
        # may need function that converts string, symmetric receive
        if client_test_string != receive_message_symmetrically(selected_user_socket, c2c_cipher, True):
            print(f"Client: {user} | Failed - Client Authorization / Symmetric communication.")
            send_message_symmetrically("Failure!", selected_user_socket, c2c_cipher)
            return

        print(f"Client: {user} | Successful - Symmetric communication.")
        send_message_symmetrically("Successful!", selected_user_socket, c2c_cipher)

        # Starts New Tkinter chat box. Not complete.
        tkinter_chat(user, c2c_cipher, selected_user_socket)

    window1 = tkinter.Tk()
    window1.title(f"Encrypted Chat")
    window1.geometry('255x620')
    window1.configure(background="black")

    l1 = tkinter.Label(window1, text="Online", bg="black", fg="white", font="none 12 bold", width='25')
    l1.grid(row=0, column=0)

    l2 = tkinter.Label(window1, text="", bg="black", fg="white", font="none 12 bold", width='25', height='28')
    l2.grid(row=1, column=0)

    e1 = tkinter.Entry(window1, text="", bg="black", fg="white", font="none 12 bold", width='25')
    e1.grid(row=2, column=0)

    # variable for update_active_users = (server_ip, server_port, server_cipher, l2)
    b1 = tkinter.Button(window1, text="Update", width=10, command=None)
    b1.grid(row=3, column=0, sticky="w", padx=40, pady=5)

    b2 = tkinter.Button(window1, text="Chat", width=10, command=get_entry)
    b2.grid(row=3, column=0, sticky="e", padx=40, pady=5)

    window1.update()

    # This timer is a terrible solution. Come up with something better.
    update_active_users()
    time_stamp = int(time.strftime("%S"))
    while True:
        print("Beginning of while true loop for window1.")
        print(f"Second time: {time.strftime('%S')} | time_stamp: {time_stamp}")
        if (abs(int(time.strftime("%S")) - time_stamp)) > 10:
            print("Time if statement true")
            update_active_users()
            time_stamp = int(time.strftime("%S"))
        window1.update()
        # Can do .2 once UI incorporates selectable boxes instead of typing.
        time.sleep(.1)


# Starts Tkinter instance in its own thread.
tkinter_window1_thread = threading.Thread(target=tkinter_main)
tkinter_window1_thread.start()


# Tkinter can only work in one thread. need to come up with a way for the main loop to receive updates
# from all the threads. The separate chats will be their own tk instance, but the main thread needs to know
# so multiple instances aren't started with one client. The main thread will mainly need updates from when
# a chat is ended. Starting, because that's executed by the mainloop, it is easy to keep up with.
# Lastly, the listening service will auto-open chat windows,
# that is a problem. Need accept, decline, and block options.



