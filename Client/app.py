import sys
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication, QWidget, QMessageBox, QInputDialog, QListWidgetItem
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject

import bcrypt # type: ignore
import socket
import base64
HOST = "127.0.0.1" # server address
PORT = 1234 # server port
BUFF_SIZE = 100 * 1024 # receive buffer size
salt = b'$2b$12$x9ZnzLMloa9lnOwnZNmMn.'

# Global variable to hold the socket
global_socket = None
# Global variable to hold the logged-in user object (for cryptography)
global_user_obj = None

import history_file as hf

import threading

history_lock = threading.Lock()
import time

from cryptography.hazmat.primitives.asymmetric import x25519
import os
import xeddsa
from cryptography.hazmat.primitives import serialization
import json
import pika
import time

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

from collections import defaultdict, deque

import base64
import socket
import os
import re

from ui_main_chat_window import Ui_MainChatWindow

LOGIN_WINDOW_WIDTH = 480
LOGIN_WINDOW_HEIGHT = 520

CHAT_WINDOW_WIDTH = 950
CHAT_WINDOW_HEIGHT = 600

AES_N_LEN = 16
AES_TAG_LEN = 16
EC_KEY_LEN = 32
EC_SIGN_LEN = 64

class SignalEmitter(QObject):
    message_received = pyqtSignal(str, str, str) # sender, receiver, message
    follow_request_received = pyqtSignal(str, str, str) # sender, receiver, message
    friend_list_updated = pyqtSignal(list) # List of friend names

def message_receiver_thread(user_obj, server_obj, hf_module, lock, signal_emitter, stop_event):
    print("[Receiver Thread] Started and listening for incoming messages.")
    
    # Variables for periodic friend list refresh
    last_known_friends = None
    refresh_counter = 0
    REFRESH_INTERVAL_SECONDS = 3 # Check every 3 seconds

    while not stop_event.is_set():
        try:
            # --- Friend List Refresh Logic ---
            if refresh_counter % REFRESH_INTERVAL_SECONDS == 0:
                current_friends = server_obj.get_following(user_obj.name)
                
                if current_friends != last_known_friends:
                    print(f"[Receiver Thread] Friend list changed. Old: {last_known_friends}, New: {current_friends}")
                    last_known_friends = current_friends
                    signal_emitter.friend_list_updated.emit(current_friends)
            
            following_list = last_known_friends if last_known_friends is not None else []
            
            result = user_obj.recv_x3dh(server_obj, is_blocking=False)

            if result:
                _ek_pa, ad = result
                if ad is None:
                    continue

                sender = ad.get('from')
                receiver = ad.get('to')
                received_message = ad.get('message')

                if sender and receiver and received_message:
                    # Check if the sender is in our list of mutuals
                    if sender not in following_list:
                        print(f"\n[+] You have a new message request from '{sender}'. Follow them to see their messages.")
                        hf_module.save_message_request(sender, receiver, received_message)
                        signal_emitter.follow_request_received.emit(sender, receiver, received_message)
                    else:
                        print(f"\n[+] New message from {sender}: {received_message}")
                        hf_module.save_message(sender, receiver, received_message, 'received', lock)
                        signal_emitter.message_received.emit(sender, receiver, received_message)
                        print(f"\nEnter command ('chat', 'follow user', 'logout'): ", end="", flush=True)

            stop_event.wait(1)
            refresh_counter += 1

        except Exception as e:
            print(f"[Receiver Thread] An error occurred: {e}")
            stop_event.wait(5)

def get_total_length(data):
    first_digit = ord(data[0]) - ord('0')
    assert(first_digit >=0 and first_digit <= 9)
    second_digit = ord(data[1]) - ord('0')
    assert(second_digit >=0 and second_digit <= 9)
    total_length = first_digit * 10 + second_digit
    return total_length

def get_total_length_5_digit(data):
    first_digit = ord(data[0]) - ord('0')
    assert(first_digit >=0 and first_digit <= 9)
    second_digit = ord(data[1]) - ord('0')
    assert(second_digit >=0 and second_digit <= 9)
    third_digit = ord(data[2]) - ord('0')
    assert(third_digit >=0 and third_digit <= 9)
    fourth_digit = ord(data[3]) - ord('0')
    assert(fourth_digit >=0 and fourth_digit <= 9)
    fifth_digit = ord(data[4]) - ord('0')
    assert(fifth_digit >=0 and fifth_digit <= 9)

    total_length = first_digit * 10000 + second_digit * 1000 + third_digit * 100 + fourth_digit * 10 + fifth_digit
    return total_length

def parse_response(data):
    decoded_data = data.decode(errors="replace")
    if len(decoded_data) < 2:
        return ("error", "Response too short for status length")

    len_status_str = decoded_data[0:2]
    try:
        len_status = int(len_status_str)
    except ValueError:
        return ("error", "Invalid response format: status length not an integer")

    if len(decoded_data) < 2 + len_status:
        return ("error", "Response too short for status content")

    status = decoded_data[2 : 2 + len_status]

    if len(decoded_data) <= 2 + len_status or decoded_data[2 + len_status] != ';':
        return (status, "Invalid response format: missing semicolon after status")

    message_len_start_index = 2 + len_status + 1
    if len(decoded_data) < message_len_start_index + 5:
        return (status, "Response too short for message length (expected 5 digits)")

    len_message_str = decoded_data[message_len_start_index : message_len_start_index + 5]
    try:
        len_message = int(len_message_str)
    except ValueError:
        return (status, "Invalid response format: message length not a 5-digit integer")

    message_start_index = message_len_start_index + 5
    if len(decoded_data) < message_start_index + len_message:
        return (status, "Response too short for message content")

    message = decoded_data[message_start_index : message_start_index + len_message]
    
    return (status, message)

def parse_response_key_bundle(data):
    decoded_data = data.decode()
    lenStatus = get_total_length(decoded_data)
    status = decoded_data[2:lenStatus + 2]

    msg_len_str = decoded_data[2 + lenStatus + 1 : 2 + lenStatus + 1 + 5]
    msg_len = int(msg_len_str)
    message = decoded_data[2 + lenStatus + 1 + 5 : 2 + lenStatus + 1 + 5 + msg_len]
    return (status, message)

def parse_simple_response(data):
    """
    Parses a response format of "llstatus;message" where the message
    is not length-prefixed.
    """
    decoded_data = data.decode()
    lenStatus = get_total_length(decoded_data)
    status = decoded_data[2:lenStatus + 2]
    
    message = decoded_data[2 + lenStatus + 1:]
    
    return (status, message)

def empty_socket_buffer(sock: socket.socket):
    """
    Reads from a socket until the receive buffer is empty.
    Temporarily sets the socket to non-blocking mode.
    """
    print("[Helper] Attempting to empty socket buffer...")
    try:
        sock.setblocking(False)
        
        while True:
            data = sock.recv(4096)
            if not data:
                print("[Helper] Socket connection closed while emptying.")
                break
            print(f"[Helper] Discarded {len(data)} bytes of stale data.")

    except BlockingIOError:
        print("[Helper] Buffer is now empty.")
        pass
    
    except Exception as e:
        print(f"[Helper] An unexpected error occurred: {e}")

    finally:
        sock.setblocking(True)

class Server:
    def __init__(self):
        self.key_bundles = {}
        self.mq = deque()
        self.message_queues = defaultdict(deque)

    def follow_user(self, current_username, target_username):
        try:
            with socket.create_connection((HOST, PORT)) as sock:
                command = f"follow user;{current_username};{target_username}"
                payload = f"{len(command):02}{command}".encode()
                sock.sendall(payload)
                data = sock.recv(BUFF_SIZE)
                status, reply = parse_simple_response(data)

                if status == "success":
                    print(f"[SUCCESS] Server says: {reply}")
                    return (True, reply)
                else:
                    print(f"[ERROR] Server says: {reply}")
                    return (False, reply)
                
        except ConnectionRefusedError:
            return (False, "Connection refused")

    def get_following(self, username):
        """Gets the list of users the current user is following."""
        try:
            with socket.create_connection((HOST, PORT)) as sock:
                command = f"get following;{username}"
                payload = f"{len(command):02}{command}".encode()
                sock.sendall(payload)
                data = sock.recv(BUFF_SIZE)
                status, reply = parse_simple_response(data)
                if status == "success":
                    contacts = reply.split(';') if reply else []
                    return contacts
                else:
                    return []
        except ConnectionRefusedError:
            return []
        
    def set_key_bundle(self, sock, username, key_bundle_str):
        try:
            print("[CLIENT] STEP 5: Sending 'publish public key' command...")
            sock.sendall(b'18publish public key')
            print("[CLIENT] STEP 6: Waiting for server ACK for 'publish public key'...")
            data = sock.recv(BUFF_SIZE)
            print("[CLIENT] STEP 7: Received server ACK.")

            if not data:
                print("[CLIENT] [ERROR] Connection closed by server.")
                return
            
            status, reply = parse_simple_response(data)
            print(f"[CLIENT] Server ACK response: Status={status}, Reply={reply}")
            if status != 'success':
                print("[CLIENT] [ERROR] Server did not approve key publishing.")
                return
            
            username_part = f"{len(username):02}{username}"
            key_bundle_bytes = key_bundle_str.encode('utf-8')
            key_bundle_part = f"{len(key_bundle_bytes):05}"
            msg = f"{username_part};{key_bundle_part}".encode('utf-8') + key_bundle_bytes

            print("[CLIENT] STEP 8A: Sending key bundle data...")
            sock.sendall(msg)
            print("[CLIENT] STEP 8B: Waiting for final confirmation from server...")
            data = sock.recv(BUFF_SIZE)
            print("[CLIENT] STEP 8C: Received final confirmation.")

            if not data:
                print("[CLIENT] [ERROR] Connection closed by server after sending keys.")
                return
            
            status, reply = parse_simple_response(data)
            print(f"[CLIENT] Final confirmation: Status={status}, Reply={reply}")

        except Exception as e:
            print(f"[CLIENT] [CRITICAL] An exception occurred in set_key_bundle: {e}")
        

    def get_key_bundle(self, username):
        if self.key_bundles.get(username):
            return self.key_bundles[username]
        with socket.create_connection((HOST, PORT)) as sock:
            sock.send(f'14get public key'.encode())

            data = sock.recv(BUFF_SIZE)
            if not data:
                print("Connection closed by server")
                return
            
            msg = f'{len(username):02}{username}'.encode()
            sock.send(msg)
            data = sock.recv(BUFF_SIZE)
            if not data:
                print("Connection closed by server")
                return
            
            status, reply = parse_response_key_bundle(data)
            if status == "success":
                jsonString = reply
                self.key_bundles[username] = self.parse_bytes_to_key_bundle(jsonString)
                print("Successfully get key bundle from server")
                return self.key_bundles[username]
            elif status == "error":
                print(f"Key bundle failed to set to the server, reason: {reply}")
            else:
                print(f"Unknown response: {status}: {reply}")


    def parse_bytes_to_key_bundle(self, str_key_bundle):
        received_data = json.loads(str_key_bundle)
        convert_to_byte_IK_p = bytes.fromhex(received_data['IK_p'])
        convert_to_byte_SPK_p = bytes.fromhex(received_data['SPK_p'])
        convert_to_byte_SPK_sig = bytes.fromhex(received_data['SPK_sig'])
        convert_to_byte_OPKs_p = []
        for i in received_data['OPKs_p']:
            convert_to_byte_OPKs_p.append(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(i)))
        convert_to_byte_OPK_p = bytes.fromhex(received_data['OPK_p'])

        received_pk = dict()
        received_pk['IK_p'] = x25519.X25519PublicKey.from_public_bytes(convert_to_byte_IK_p)
        received_pk['SPK_p'] = x25519.X25519PublicKey.from_public_bytes(convert_to_byte_SPK_p)
        received_pk['SPK_sig'] = convert_to_byte_SPK_sig
        received_pk['OPKs_p'] = convert_to_byte_OPKs_p
        received_pk['OPK_p'] = x25519.X25519PublicKey.from_public_bytes(convert_to_byte_OPK_p)
        return received_pk

    def send(self, to: str, message: bytes):
        """
        Simulate sending a message to a user.
        Optionally track the sender.
        """
        connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        channel = connection.channel()
        channel.queue_declare(queue=to)
        channel.basic_publish(exchange='',
                                routing_key=to,
                                body=message)
        connection.close()

    def recv(self, to: str):
        """
        Simulate receiving a message for a user.
        Returns (sender, message) or (None, None) if empty.
        """
        connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
        channel = connection.channel()
        channel.queue_declare(queue=to)

        def callback(ch, method, properties, body):
            self.mq.append(body)
            ch.stop_consuming()

        channel.basic_consume(queue=to, on_message_callback=callback, auto_ack=True)

        timeout = 1

        start_time = time.time()
        while time.time() - start_time < timeout:
            connection.process_data_events(time_limit=0.1)

            if self.mq:
                print(" [*] Message received, exiting wait loop.")
                break
            
        connection.close()

        if self.mq:
            return True
        else:
            return False
    
    def blocking_recv(self, to: str):
        """
                blocking until a message is available
        """
        connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
        channel = connection.channel()
        channel.queue_declare(queue=to)

        def callback(ch, method, properties, body):
            self.mq.append(body)
            ch.stop_consuming()

        channel.basic_consume(queue=to, on_message_callback=callback, auto_ack=True)
        channel.start_consuming()

    def pop_from_mq(self):
        if len(self.mq) == 0:
            return None
        return self.mq.popleft()

class User:
    def __init__(self, name, MAX_OPK_NUM):
        self.name = name

        # Identity Key
        self.IK_s = x25519.X25519PrivateKey.generate()
        self.IK_p = self.IK_s.public_key()

        # Signed PreKey
        self.SPK_s = x25519.X25519PrivateKey.generate()
        self.SPK_p = self.SPK_s.public_key()

        # Nonce for XEdDSA signing (must be 64 bytes)
        self._spk_nonce = os.urandom(64)

        # Convert identity private key to XEdDSA format
        ik_priv = xeddsa.Priv(self.IK_s.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ))


        # Generate signature: sign SPK_p using IK_s
        spk_pub_bytes = self.SPK_p.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        self.SPK_sig = xeddsa.ed25519_priv_sign(ik_priv, spk_pub_bytes, self._spk_nonce)

        # One-Time PreKeys
        self.OPKs = []
        self.OPKs_p = []
        for _ in range(MAX_OPK_NUM):
            sk = x25519.X25519PrivateKey.generate()
            pk = sk.public_key()
            self.OPKs.append((sk, pk))
            self.OPKs_p.append(pk)

        # For sessions
        self.key_bundles = {}
        self.dr_keys = {}
        
        self.ik_to_username_map = {}

    def publish(self):
        return {
            'IK_p': self.IK_p,
            'SPK_p': self.SPK_p,
            'SPK_sig': self.SPK_sig,
            'OPKs_p': self.OPKs_p,
            'OPK_p': self.OPKs_p[0], # Pick one OPK
        }
    
    def store_keys(self):
        public_bundle = self.dump_pk_to_json()
        private_bundle = self.dump_priv_to_json()

        public_filename = f"{self.name}_public_keys.txt"
        private_filename = f"{self.name}_private_keys.txt"

        # --- Storing the Public Keys ---
        print(f"Storing public key bundle to '{public_filename}'...")
        with open(public_filename, 'w') as f:
            f.write(public_bundle)
        print("...public keys saved.")

        # --- Storing the Private Keys ---
        print(f"Storing private key bundle to '{private_filename}'...")
        with open(private_filename, 'w') as f:
            f.write(private_bundle.decode())
        print("...private keys saved.")

    def load_keys(self):
        """
        Reads the JSON files and deserializes them back into Python dictionaries.
        """
        public_filename = f"{self.name}_public_keys.txt"
        private_filename = f"{self.name}_private_keys.txt"
        
        public_data = None
        private_data = None

        print("\n--- 2. Loading key bundles from files ---")
        
        # --- Loading the Public Keys ---
        try:
            with open(public_filename, 'r') as f:
                public_data = json.load(f)
                public_key_bundle = self.parse_pubkey_dict_to_dict(public_data)
                self.IK_p = public_key_bundle['IK_p']
                self.SPK_p = public_key_bundle['SPK_p']
                self.SPK_sig = public_key_bundle['SPK_sig']
                self.OPKs_p = public_key_bundle['OPKs_p']
            print(f"Successfully loaded data from '{public_filename}'")
        except FileNotFoundError:
            print(f"ERROR: File '{public_filename}' not found.")
            return False
        except json.JSONDecodeError:
            print(f"ERROR: Could not decode JSON from '{public_filename}'.")
            return False

        # --- Loading the Private Keys ---
        try:
            with open(private_filename, 'r') as f:
                private_data = json.load(f)
                private_key_bundle = self.parse_privkey_dict_to_dict(private_data)
                self.IK_s = private_key_bundle['IK_s']
                self.SPK_s = private_key_bundle['SPK_s']

                self.OPKs = private_key_bundle['OPKs']
            print(f"Successfully loaded data from '{private_filename}'")
        except FileNotFoundError:
            print(f"ERROR: File '{private_filename}' not found.")
            return False
        except json.JSONDecodeError:
            print(f"ERROR: Could not decode JSON from '{private_filename}'.")
            return False
            
        return True
    
    def _serialize_key(self, key_obj):
        """Helper to safely convert a key object to a hex string."""
        if hasattr(key_obj, 'private_bytes'): # Catches private keys
            return key_obj.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ).hex()
        if hasattr(key_obj, 'public_bytes'): # Catches public keys
            return key_obj.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex()
        if isinstance(key_obj, bytes): # Catches SK and SPK_sig
            return key_obj.hex()
        return key_obj

    def save_sessions(self):
        """Saves the current session data to a file."""
        session_filename = f"{self.name}_sessions.json"
        print(f"--- Saving session data to '{session_filename}' ---")
        
        storable_bundles = {}
        for partner, bundle in self.key_bundles.items():
            storable_bundles[partner] = {k: self._serialize_key(v) for k, v in bundle.items() if k != 'OPKs_p'}
            print(f"  > Saving session for partner '{partner}' with keys: {list(storable_bundles[partner].keys())}")

        try:
            with open(session_filename, 'w') as f:
                json.dump(storable_bundles, f, indent=2)
            print("--- Sessions saved successfully ---\n")
        except Exception as e:
            print(f"--- Error saving sessions: {e} ---\n")

    def load_sessions(self):
        """Loads and reconstructs session data from a file."""
        session_filename = f"{self.name}_sessions.json"
        print(f"--- Loading session data from '{session_filename}' ---")
        try:
            with open(session_filename, 'r') as f:
                storable_bundles = json.load(f)

            for partner, bundle in storable_bundles.items():
                self.key_bundles[partner] = {}
                for k, v_hex in bundle.items():
                    if not isinstance(v_hex, str) or len(v_hex) == 0:
                        continue
                    try:
                        v_bytes = bytes.fromhex(v_hex)
                        # Key reconstruction logic
                        if k in ['EK_s', 'SPK_s']:
                             self.key_bundles[partner][k] = x25519.X25519PrivateKey.from_private_bytes(v_bytes)
                        elif k in ['IK_p', 'SPK_p', 'OPK_p', 'EK_p']:
                            self.key_bundles[partner][k] = x25519.X25519PublicKey.from_public_bytes(v_bytes)
                            if k == 'IK_p': self.ik_to_username_map[v_bytes] = partner
                        else: # Handles SK and SPK_sig, which are raw bytes
                            self.key_bundles[partner][k] = v_bytes
                    except Exception as e:
                        print(f"  > Warning: Skipping corrupt key '{k}' for partner '{partner}': {e}")
            print(f"--- Sessions loaded successfully. Current partners in memory: {list(self.key_bundles.keys())} ---\n")
        except FileNotFoundError:
            print("--- No session file found. Starting fresh. ---\n")
        except Exception as e:
            print(f"--- Error loading sessions: {e} ---\n")


    def parse_pubkey_dict_to_dict(self, dict_key_bundle):
        convert_to_byte_IK_p = bytes.fromhex(dict_key_bundle['IK_p'])
        convert_to_byte_SPK_p = bytes.fromhex(dict_key_bundle['SPK_p'])
        convert_to_byte_SPK_sig = bytes.fromhex(dict_key_bundle['SPK_sig'])
        convert_to_byte_OPKs_p = []
        for i in dict_key_bundle['OPKs_p']:
            convert_to_byte_OPKs_p.append(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(i)))
        convert_to_byte_OPK_p = bytes.fromhex(dict_key_bundle['OPK_p'])

        received_pk = dict()
        received_pk['IK_p'] = x25519.X25519PublicKey.from_public_bytes(convert_to_byte_IK_p)
        received_pk['SPK_p'] = x25519.X25519PublicKey.from_public_bytes(convert_to_byte_SPK_p)
        received_pk['SPK_sig'] = convert_to_byte_SPK_sig
        received_pk['OPKs_p'] = convert_to_byte_OPKs_p
        received_pk['OPK_p'] = x25519.X25519PublicKey.from_public_bytes(convert_to_byte_OPK_p)
        return received_pk
    
    def parse_privkey_dict_to_dict(self, dict_key_bundle):
        convert_to_byte_IK_s = bytes.fromhex(dict_key_bundle['IK_s'])
        convert_to_byte_SPK_s = bytes.fromhex(dict_key_bundle['SPK_s'])
        convert_to_byte_OPKs = []
        for i in dict_key_bundle['OPKs']:
            first_element = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(i[0]))
            second_element = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(i[1]))
            convert_to_byte_OPKs.append((first_element, second_element))

        received_pk = dict()
        received_pk['IK_s'] = x25519.X25519PrivateKey.from_private_bytes(convert_to_byte_IK_s)
        received_pk['SPK_s'] = x25519.X25519PrivateKey.from_private_bytes(convert_to_byte_SPK_s)
        received_pk['OPKs'] = convert_to_byte_OPKs
        return received_pk

    def get_key_bundle(self, server_obj, user_name):
        if user_name in self.key_bundles and 'SK' in self.key_bundles[user_name] and user_name in self.dr_keys:
            print('Already stored ' + user_name + ' locally, no need handshake again')
            return True

        server_obj.get_key_bundle(user_name)

        if user_name not in server_obj.key_bundles:
            print(f"Failed to retrieve key bundle for {user_name} from server.")
            return False

        fresh_public_bundle = server_obj.key_bundles[user_name]

        if user_name not in self.key_bundles:
            self.key_bundles[user_name] = {}
        
        self.key_bundles[user_name].update(fresh_public_bundle)

        return True

    def initial_handshake(self, server_obj, user_name):
        if self.get_key_bundle(server_obj, user_name):
            friend_ik_p = self.key_bundles[user_name]['IK_p']
            friend_ik_p_bytes = self.dump_publickey(friend_ik_p)
            self.ik_to_username_map[friend_ik_p_bytes] = user_name

            sk = x25519.X25519PrivateKey.generate()
            pk = sk.public_key()

            self.key_bundles[user_name]['EK_s'] = sk
            self.key_bundles[user_name]['EK_p'] = pk

            opk_list = self.key_bundles[user_name].get('OPKs_p', [])
            if not opk_list:
                print(f"No OPK available from {user_name}. Cannot initiate handshake.")
                return False
            
            self.key_bundles[user_name]['OPK_p'] = opk_list.pop(0)

            return True
        return False


    def x3dh_KDF(self, key_material: bytes) -> bytes:
        KDF_F = b'\xff' * 32
        KDF_LEN = 32
        KDF_SALT = b'\x00' * KDF_LEN
        km = KDF_F + key_material
        return HKDF(km, KDF_LEN, KDF_SALT, SHA256, 1)

    def generate_send_secret_key(self, user_name: str):
        key_bundle = self.key_bundles[user_name]

        DH_1 = self.IK_s.exchange(key_bundle['SPK_p'])
        DH_2 = key_bundle['EK_s'].exchange(key_bundle['IK_p'])
        DH_3 = key_bundle['EK_s'].exchange(key_bundle['SPK_p'])
        DH_4 = key_bundle['EK_s'].exchange(key_bundle['OPK_p'])

        key_bundle['SK'] = self.x3dh_KDF(DH_1 + DH_2 + DH_3 + DH_4)
        return key_bundle['SK']

    def dump_privatekey(self, private_key):
        private_key = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_key

    def dump_publickey(self, public_key):
        public_key = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return public_key

    def dump_pk_to_json(self):
        pk = self.publish()

        published_dict = dict()
        published_dict['IK_p'] = self.dump_publickey(pk['IK_p']).hex()
        published_dict['SPK_p'] = self.dump_publickey(pk['SPK_p']).hex()
        published_dict['SPK_sig'] = pk['SPK_sig'].hex()
        published_dict['OPKs_p'] = []
        for i in pk['OPKs_p']:
            published_dict['OPKs_p'].append(self.dump_publickey(i).hex())
        published_dict['OPK_p'] = self.dump_publickey(pk['OPK_p']).hex()

        return json.dumps(published_dict)
    
    def dump_priv_to_json(self):
        private = {
            'IK_s': self.IK_s,
            'SPK_s': self.SPK_s,
            'OPKs': self.OPKs,
        }

        published_dict = dict()
        published_dict['IK_s'] = self.dump_privatekey(private['IK_s']).hex()
        published_dict['SPK_s'] = self.dump_privatekey(private['SPK_s']).hex()
        published_dict['OPKs'] = []
        for i in private['OPKs']:
            published_dict['OPKs'].append((self.dump_privatekey(i[0]).hex(), self.dump_publickey(i[1]).hex()))

        return json.dumps(published_dict).encode('utf-8')

    def build_x3dh(self, server_obj, to, ad):
        b_ad = (json.dumps({
        'from': self.name,
        'to': to,
        'message': ad
        })).encode('utf-8')

        key_bundle = self.key_bundles[to]
        key_comb = self.dump_publickey(self.IK_p) + self.dump_publickey(key_bundle['EK_p']) + self.dump_publickey(key_bundle['OPK_p'])
        ik_priv = xeddsa.Priv(self.IK_s.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ))

        nonce = os.urandom(64)

        signature = xeddsa.ed25519_priv_sign(ik_priv, key_comb + b_ad, nonce)
        
        nonce = get_random_bytes(AES_N_LEN)
        cipher = AES.new(key_bundle['SK'], AES.MODE_GCM, nonce=nonce, mac_len=AES_TAG_LEN)
        ciphertext, tag = cipher.encrypt_and_digest(signature + self.dump_publickey(self.IK_p) + self.dump_publickey(key_bundle['IK_p']) + b_ad)

        message = key_comb + nonce + tag + ciphertext
        server_obj.send(to, message)

    def search_OPK_lst(self, opk_pub_bytes: bytes):
        for i, (sk, pk) in enumerate(self.OPKs):
            pk_bytes = pk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            if pk_bytes == opk_pub_bytes:
                self.OPKs.pop(i)
                self.OPKs_p.pop(i)
                return sk
        return None

    def recv_x3dh(self, server_obj, is_blocking=False):
        """
        Receives and decrypts a message, handling both existing and reset sessions.
        """
        if is_blocking:
            server_obj.blocking_recv(self.name)
        else:
            message_available = server_obj.recv(self.name)
            if not message_available:
                return None
        
        message = server_obj.pop_from_mq()
        if message is None:
            return None

        IK_pa_bytes = message[:EC_KEY_LEN]
        EK_pa_bytes = message[EC_KEY_LEN:EC_KEY_LEN*2]
        OPK_pb_bytes = message[EC_KEY_LEN*2:EC_KEY_LEN*3]
        nonce = message[EC_KEY_LEN*3:EC_KEY_LEN*3+AES_N_LEN]
        tag = message[EC_KEY_LEN*3+AES_N_LEN:EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN]
        ciphertext = message[EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN:]

        sender_name = self.ik_to_username_map.get(IK_pa_bytes)
        stored_sk = self.key_bundles.get(sender_name, {}).get('SK')
        
        if stored_sk:
            print(f"[+] Existing session with '{sender_name}' found. Trying stored SK...")
            message_ad = self.x3dh_decrypt_and_verify(stored_sk, IK_pa_bytes, EK_pa_bytes, OPK_pb_bytes, nonce, tag, ciphertext)
            if message_ad:
                return EK_pa_bytes, message_ad
            
            print(f"[!] Decryption with stored key for '{sender_name}' failed. Attempting session re-establishment.")

        print(f"[+] No valid session found. Performing full handshake calculation...")
        new_sk = self.generate_recv_secret_key(IK_pa_bytes, EK_pa_bytes, OPK_pb_bytes)
        
        if not new_sk:
            print("[!] CRITICAL: Handshake calculation failed. Decryption aborted.")
            return None

        message_ad = self.x3dh_decrypt_and_verify(new_sk, IK_pa_bytes, EK_pa_bytes, OPK_pb_bytes, nonce, tag, ciphertext)

        if message_ad:
            print(f"[+] Session with '{sender_name}' successfully established/reset.")
            
            if not sender_name:
                sender_name = message_ad.get('from')
                self.ik_to_username_map[IK_pa_bytes] = sender_name
            
            if sender_name:
                if sender_name not in self.key_bundles:
                    self.key_bundles[sender_name] = {}
                self.key_bundles[sender_name]['SK'] = new_sk
                print(f"   > Stored new session key for '{sender_name}'.")
            
            return EK_pa_bytes, message_ad
        else:
            print("[!] CRITICAL: Decryption failed after full handshake. Message is corrupt or invalid.")
            return None

    def generate_recv_secret_key(self, IK_pa_bytes, EK_pa_bytes, OPK_pb_bytes):
        OPK_sb = self.search_OPK_lst(OPK_pb_bytes)
        if OPK_sb is None:
            print("No matching OPK found in local store.")
            return None

        IK_pa = x25519.X25519PublicKey.from_public_bytes(IK_pa_bytes)
        EK_pa = x25519.X25519PublicKey.from_public_bytes(EK_pa_bytes)

        DH_1 = self.SPK_s.exchange(IK_pa)
        DH_2 = self.IK_s.exchange(EK_pa)
        DH_3 = self.SPK_s.exchange(EK_pa)
        DH_4 = OPK_sb.exchange(EK_pa)

        return self.x3dh_KDF(DH_1 + DH_2 + DH_3 +DH_4)
        
    def x3dh_decrypt_and_verify(self, sk, IK_pa, EK_pa, OPK_pb, nonce, tag, ciphertext):
        cipher = AES.new(sk, AES.MODE_GCM, nonce=nonce, mac_len=AES_TAG_LEN)
        p_all = None
        try:
            p_all = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            print('Unable to verify/decrypt ciphertext (Tag mismatch or decryption error)')
            return None
        except Exception as e:
            print(f'Exception during decryption: {e}')
            return None

        if p_all is None:
            return None

        sign = p_all[:EC_SIGN_LEN]
        IK_pa_p = p_all[EC_SIGN_LEN:EC_SIGN_LEN+EC_KEY_LEN]
        IK_pb_p = p_all[EC_SIGN_LEN+EC_KEY_LEN:EC_SIGN_LEN+EC_KEY_LEN*2]
        ad_bytes = p_all[EC_SIGN_LEN+EC_KEY_LEN*2:]

        IK_pb = self.dump_publickey(self.IK_p)

        if IK_pa != IK_pa_p:
            print("Sender identity key mismatch during verification!")
            return None

        if IK_pb != IK_pb_p:
            print("Receiver identity key mismatch during verification!")
            return None
        
        print("Decryption and identity check passed!")
        return json.loads(ad_bytes.decode())
            
    def receive_all_incoming_message(self, server_obj, hf_module, lock, following_list):
        """
        Receives all pending offline messages, saves them, and returns a list of senders.
        """
        print("Checking for offline messages...")
        new_message_senders = set()

        while True:
            result = self.recv_x3dh(server_obj, is_blocking=False)
            
            if result is None:
                break
            
            ad = result[1]
            if ad is None:
                continue

            sender = ad.get('from')
            receiver = ad.get('to')
            received_message = ad.get('message')

            if sender and receiver and received_message:
                if sender not in following_list:
                    print(f"[Offline Request] You have an offline message from '{sender}'.")
                    hf_module.save_message_request(sender, receiver, received_message)
                else:
                    print(f"[Offline Message] Received and saved a message from {sender}.")
                    hf_module.save_message(sender, receiver, received_message, 'received', lock)
                    # Add the sender to our set of users with new messages
                    new_message_senders.add(sender)
        
        # Return the list of unique senders
        return list(new_message_senders)
                
# Global instance of Server
server = Server()

class MainChatWindow(QDialog):
    def __init__(self, logged_in_username):
        super().__init__()
        self.ui = Ui_MainChatWindow()
        self.ui.setupUi(self)

        self.ui.chatDisplay.setReadOnly(True)

        self.logged_in_username = logged_in_username
        self.current_chat_partner = None

        global global_user_obj
        if global_user_obj is None:
            print("Warning: global_user_obj is None in MainChatWindow, attempting to load keys.")
            global_user_obj = User(self.logged_in_username, 1000)
            if not global_user_obj.load_keys():
                QMessageBox.critical(self, "Key Error", "Failed to load cryptographic keys for current user. Please restart.")
                return
            global_user_obj.load_sessions()
        self.user_crypto = global_user_obj

        self.signal_emitter = SignalEmitter()
        self.signal_emitter.message_received.connect(self.on_message_received)
        self.signal_emitter.follow_request_received.connect(self.on_follow_request_received)
        self.signal_emitter.friend_list_updated.connect(self.populate_friends_list)

        self.stop_receiver_thread = threading.Event()
        self.start_message_receiver_thread()

        self.ui.contentStackedWidget.setCurrentWidget(self.ui.welcomePage)
        self.ui.chattingWithLabel.setText(f"Welcome, {self.logged_in_username}!")

        self.ui.sendButton.setEnabled(False)
        self.ui.messageLineEdit.textChanged.connect(self.update_send_button_state)
        self.ui.sendButton.clicked.connect(self.send_message)

        self.ui.addFriendButton.clicked.connect(self.show_add_friend_page)
        self.ui.sendFriendRequestButton.clicked.connect(self.send_friend_request)
        self.ui.logoutButton.clicked.connect(self.logout)
        
        initial_friends = server.get_following(self.logged_in_username)
        self.populate_friends_list(initial_friends)

        QTimer.singleShot(100, self.process_offline_messages)

    def process_offline_messages(self):
        """
        Checks for offline messages and highlights the senders in the UI.
        """
        senders_with_new_messages = self.user_crypto.receive_all_incoming_message(
            server, hf, history_lock, self.current_following_list
        )

        if senders_with_new_messages:
            print(f"You have new offline messages from: {senders_with_new_messages}")
            for sender in senders_with_new_messages:
                self.highlight_friend_in_list(sender)

    def start_message_receiver_thread(self):
        self.receiver_thread = threading.Thread(
            target=message_receiver_thread,
            args=(self.user_crypto, server, hf, history_lock, self.signal_emitter, self.stop_receiver_thread),
            daemon=True
        )
        self.receiver_thread.start()
        print("[App] Message receiver thread started.")

    def populate_friends_list(self, friends_list):
        """
        Populates the friends list widget from a given list.
        This now acts as a slot for signals.
        """
        self.ui.friendsListWidget.clear()
        # Store the current list for other parts of the app to use
        self.current_following_list = friends_list
        for friend in friends_list:
            item = QListWidgetItem(friend)
            self.ui.friendsListWidget.addItem(item)
        self.ui.friendsListWidget.itemClicked.connect(self.friend_selected)
        print(f"Friends list updated: {self.current_following_list}")


    def friend_selected(self, item):
        """
        Handles selection of a friend from the list.
        Switches to the chat page and updates the 'chattingWithLabel'.
        """
        item.setBackground(Qt.transparent)
        item.setToolTip("")

        friend_name = item.text()
        self.current_chat_partner = friend_name # Set current chat partner
        self.ui.chattingWithLabel.setText(f"Chatting with: {friend_name}")
        self.ui.contentStackedWidget.setCurrentWidget(self.ui.chatPage)
        self.ui.chatDisplay.clear() # Clear previous chat history
        self.ui.messageLineEdit.clear() # Clear message input field
        self.ui.messageLineEdit.setFocus()

        # Load chat history for the selected friend
        self.load_chat_history(friend_name)


    def load_chat_history(self, friend_name):
        self.ui.chatDisplay.append(f"--- Chat history with {friend_name} ---")
        chat_history = hf.get_chat_history(self.logged_in_username, friend_name, history_lock)

        for msg in chat_history:
            sender = msg['sender']
            message_content = msg['message']
            msg_type = msg['type']

            if msg_type == 'sent':
                self.ui.chatDisplay.append(f"<span style='color: #6C5B7B;'>You:</span> {message_content}")
            elif msg_type == 'received':
                self.ui.chatDisplay.append(f"<span style='color: #88B04B;'>{sender}:</span> {message_content}")
        
        self.ui.chatDisplay.append("-----------------------------")
        QTimer.singleShot(10, lambda: self.ui.chatDisplay.verticalScrollBar().setValue(self.ui.chatDisplay.verticalScrollBar().maximum()))

    def send_message(self):
        message_content = self.ui.messageLineEdit.text().strip()
        if not message_content:
            return

        if not self.current_chat_partner:
            QMessageBox.warning(self, "No Chat Selected", "Please select a friend to chat with first.")
            return

        try:
            partner_session_data = self.user_crypto.key_bundles.get(self.current_chat_partner, {})
            if 'SK' not in partner_session_data or 'EK_p' not in partner_session_data:
                print(f"Session is incomplete with {self.current_chat_partner}. Running handshake...")
                if not self.user_crypto.initial_handshake(server, self.current_chat_partner):
                    QMessageBox.critical(self, "Handshake Failed", f"Could not establish secure session with {self.current_chat_partner}.")
                    return

            if 'SK' not in self.user_crypto.key_bundles[self.current_chat_partner]:
                print(f"Generating SK for {self.current_chat_partner} after handshake.")
                self.user_crypto.generate_send_secret_key(self.current_chat_partner)

            self.user_crypto.build_x3dh(server, self.current_chat_partner, message_content)
            hf.save_message(self.logged_in_username, self.current_chat_partner, message_content, 'sent', history_lock)

            self.ui.chatDisplay.append(f"<span style='color: #6C5B7B;'>You:</span> {message_content}")
            self.ui.messageLineEdit.clear()
            self.ui.messageLineEdit.setFocus()

            QTimer.singleShot(10, lambda: self.ui.chatDisplay.verticalScrollBar().setValue(self.ui.chatDisplay.verticalScrollBar().maximum()))

        except ValueError as ve:
            QMessageBox.critical(self, "Handshake Error", str(ve))
            print(f"Handshake ValueError: {ve}")
        except Exception as e:
            QMessageBox.critical(self, "Message Send Error", f"Failed to send message: {e}")
            print(f"Error sending message: {e}")

    def on_message_received(self, sender, receiver, message):
        """Slot to handle messages received from the background thread."""
        print(f"[UI] Displaying message from {sender} in UI.")
        if self.current_chat_partner == sender:
            self.ui.chatDisplay.append(f"<span style='color: #88B04B;'>{sender}:</span> {message}")
            QTimer.singleShot(10, lambda: self.ui.chatDisplay.verticalScrollBar().setValue(self.ui.chatDisplay.verticalScrollBar().maximum()))
        else:
            # If the message is not from the current chat partner, just highlight their name.
            self.highlight_friend_in_list(sender)

    def on_follow_request_received(self, sender, receiver, message):
        """Slot to handle follow requests received from the background thread."""
        print(f"[UI] Displaying follow request from {sender} in UI.")
        # Just highlight the user in the list with the request color.
        self.highlight_friend_in_list(sender, is_request=True)

    def highlight_friend_in_list(self, friend_name, is_request=False):
        for i in range(self.ui.friendsListWidget.count()):
            item = self.ui.friendsListWidget.item(i)
            if item.text() == friend_name:
                if is_request:
                    item.setBackground(Qt.red)
                    item.setToolTip("New message request!")
                else:
                    item.setBackground(Qt.yellow)
                    item.setToolTip("New unread message(s)!")
                break

    def show_add_friend_page(self):
        """Switches the content area to the Add Friend page."""
        # Clear the logical chat partner to ensure notifications work correctly.
        self.current_chat_partner = None
        
        self.ui.friendsListWidget.clearSelection()

        self.ui.contentStackedWidget.setCurrentWidget(self.ui.addFriendPage)
        self.ui.newFriendUsernameLineEdit.clear() # Clear any previous input
        self.ui.addFriendStatusLabel.clear() # Clear any previous status message
        self.ui.newFriendUsernameLineEdit.setFocus()

    def send_friend_request(self):
        username_to_add = self.ui.newFriendUsernameLineEdit.text().strip()
        if not username_to_add:
            self.ui.addFriendStatusLabel.setText("Please enter a username.")
            self.ui.addFriendStatusLabel.setStyleSheet("color: red;")
            return

        if username_to_add == self.logged_in_username:
            self.ui.addFriendStatusLabel.setText("You cannot follow yourself.")
            self.ui.addFriendStatusLabel.setStyleSheet("color: red;")
            return

        success, message = server.follow_user(self.logged_in_username, username_to_add)

        if success:
            self.ui.addFriendStatusLabel.setText(f"Success: {message}")
            self.ui.addFriendStatusLabel.setStyleSheet("color: lightgreen;")
            self.ui.newFriendUsernameLineEdit.clear()
            initial_friends = server.get_following(self.logged_in_username)
            self.populate_friends_list(initial_friends)
            print(f"Checking for pending messages from {username_to_add} after following...")
            hf.promote_requests_to_history(username_to_add, self.logged_in_username, history_lock)
        else:
            self.ui.addFriendStatusLabel.setText(f"Failed: {message}")
            self.ui.addFriendStatusLabel.setStyleSheet("color: orange;")

    def update_send_button_state(self):
        self.ui.sendButton.setEnabled(bool(self.ui.messageLineEdit.text()))

    def logout(self):
        reply = QMessageBox.question(self, 'Logout', 'Are you sure you want to log out?',
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                        QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            print("Logging out...")
            
            self.user_crypto.save_sessions()
            
            print("Signaling receiver thread to stop...")
            self.stop_receiver_thread.set()
            
            self.receiver_thread.join(timeout=2)  
            print("Receiver thread stopped.")

            global global_socket, global_user_obj
            if global_socket:
                try:
                    global_socket.close()
                    print("Global socket closed upon logout.")
                except Exception as e:
                    print(f"Error closing global socket during logout: {e}")
                global_socket = None
            global_user_obj = None

            login_screen = LoginScreen()
            widget.addWidget(login_screen)
            widget.setCurrentIndex(widget.currentIndex() + 1)
            widget.removeWidget(self)

    def closeEvent(self, event):
        self.logout()
        event.accept()

class LoginScreen(QDialog):
    def __init__(self):
        super(LoginScreen, self).__init__()
        loadUi("Login.ui",self)
        self.Password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.Login.clicked.connect(self.loginfunction)
        self.registerButton.clicked.connect(self.gotoregister)
        self.forgotPasswordButton.clicked.connect(self.gotoforgot)
        self.sock = None
        self.check_and_connect()
        self.Username.textChanged.connect(self.check_fields)
        self.Password.textChanged.connect(self.check_fields)
        self.ErrorLogin.setText("") 
        self.check_fields()
        widget.setFixedSize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)

    def check_and_connect(self):
        global global_socket
        if global_socket is None:
            try:
                global_socket = socket.create_connection((HOST, PORT))
                print(f"Connected to {HOST}:{PORT}")
                self.sock = global_socket
                self.registerButton.setEnabled(True)
                self.forgotPasswordButton.setEnabled(True)
                self.check_fields()
            except ConnectionRefusedError:
                QMessageBox.critical(self, "Connection Error", "Could not connect to the server. Please ensure the server is running.")
                self.Login.setEnabled(False)
                self.registerButton.setEnabled(False)
                self.forgotPasswordButton.setEnabled(False)
                self.sock = None
            except Exception as e:
                QMessageBox.critical(self, "Network Error", f"An unexpected network error occurred: {e}")
                self.Login.setEnabled(False)
                self.registerButton.setEnabled(False)
                self.forgotPasswordButton.setEnabled(False)
                self.sock = None
        else:
            self.sock = global_socket
            self.registerButton.setEnabled(True)
            self.forgotPasswordButton.setEnabled(True)
            self.check_fields()

    def check_fields(self):
        is_username_filled = bool(self.Username.text())
        is_password_filled = bool(self.Password.text())
        can_enable_button = is_username_filled and is_password_filled and self.sock is not None
        self.Login.setEnabled(can_enable_button)
        if can_enable_button:
            self.Login.setStyleSheet("background-color: rgb(138, 44, 138);")
        else:
            self.Login.setStyleSheet("")

    def closeEvent(self, event):
        global global_socket
        if global_socket:
            try:
                global_socket.close()
                print("Global socket closed from LoginScreen's closeEvent.")
            except Exception as e:
                print(f"Error closing global socket in LoginScreen: {e}")
            global_socket = None
        super().closeEvent(event)

    def loginfunction(self):
        global global_socket, global_user_obj
        if not self.sock:
            QMessageBox.warning(self, "Connection Status", "Not connected to the server.")
            return

        username = self.Username.text()
        password = self.Password.text()

        try:
            self.sock.sendall(b"05login")
            self.sock.sendall(f"{len(username):02}{username}".encode())

            hashed = bcrypt.hashpw(password.encode(), salt)
            self.sock.sendall(f"{len(hashed):02}".encode() + hashed)

            data = self.sock.recv(BUFF_SIZE)
            
            if not data:
                QMessageBox.critical(self, "Connection Error", "Server closed the connection.")
                return

            status, reply = parse_simple_response(data)
            if status == "success":
                self.ErrorLogin.setText("")
                
                global_user_obj = User(username, 1000)
                if not global_user_obj.load_keys():
                    QMessageBox.critical(self, "Key Error", "Cryptographic keys not found or corrupted.")
                    global_user_obj = None
                    return

                global_user_obj.load_sessions()
                print(f"User {username} successfully logged in.")
                self.gotoMainChatWindow(username)
            else:
                self.ErrorLogin.setText("Invalid username or password")

        except Exception as e:
            QMessageBox.critical(self, "Login Error", f"An unexpected error occurred: {e}")
            if self.sock:
                self.sock.close()
            self.sock = None
            global_socket = None

    def gotoregister(self):
        register = RegisterScreen("", "", "")
        widget.addWidget(register)
        widget.setCurrentIndex(widget.currentIndex()+1)
        widget.setFixedSize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)

    def gotoforgot(self):
        forgot = ForgotScreen()
        widget.addWidget(forgot)
        widget.setCurrentIndex(widget.currentIndex() + 1)
        widget.setFixedSize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)

    def gotoMainChatWindow(self, username):
        main_chat_window = MainChatWindow(username)
        widget.addWidget(main_chat_window)
        widget.setCurrentIndex(widget.currentIndex() + 1)
        widget.setFixedSize(CHAT_WINDOW_WIDTH, CHAT_WINDOW_HEIGHT)

class ForgotScreen(QDialog):
    def __init__(self, email=""):
        super(ForgotScreen, self).__init__()
        loadUi("ResetPasswordMasukEmail.ui",self)
        self.sendOTP.clicked.connect(self.OTPFunction)
        self.goBack.clicked.connect(self.gotologin)
        
        self.sock = None
        self.check_and_connect()

        self.ErrorEmailReset.setText("")
        self.Email.setText(email)

        self.Email.textChanged.connect(self.check_fields)

        self.check_fields()

    def check_and_connect(self):
        global global_socket # Declare global first
        if global_socket is None:
            try:
                global_socket = socket.create_connection((HOST, PORT))
                print(f"Connected to {HOST}:{PORT}")
                self.sock = global_socket
                self.check_fields()
            except ConnectionRefusedError:
                QMessageBox.critical(self, "Connection Error", "Could not connect to the server. Please ensure the server is running.")
                self.sendOTP.setEnabled(False)
                self.sock = None
            except Exception as e:
                QMessageBox.critical(self, "Network Error", f"An unexpected network error occurred: {e}")
                self.sendOTP.setEnabled(False)
                self.sock = None
        else:
            self.sock = global_socket
            self.check_fields()

    def check_fields(self):
        is_email_filled = bool(self.Email.text())
        can_enable_button = is_email_filled and self.sock is not None
        
        self.sendOTP.setEnabled(can_enable_button)
        if can_enable_button:
            self.sendOTP.setStyleSheet("background-color: rgb(138, 44, 138);")
        else:
            self.sendOTP.setStyleSheet("")

    def gotologin(self):
        login = LoginScreen()
        widget.addWidget(login)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def OTPFunction(self):
        self.ErrorEmailReset.setText("")

        global global_socket
        if not self.sock:
            QMessageBox.warning(self, "Connection Status", "Not connected to the server.")
            return

        email = self.Email.text()
        if not email:
            self.ErrorEmailReset.setText("Please enter your email!")
            return

        try:
            self.sock.sendall(b"14reset password")

            self.sock.sendall(f"{len(email):02}{email}".encode())

            data = self.sock.recv(BUFF_SIZE)
            if not data:
                QMessageBox.critical(self, "Connection Error", "Server closed the connection unexpectedly.")
                if self.sock: self.sock.close()
                self.sock = None
                global_socket = None
                return
            
            status, reply = parse_simple_response(data)
            if status != "success":
                self.ErrorEmailReset.setText(f"Error sending OTP: {reply}")
                return
            
            input_otp = InputOTP(email)
            widget.addWidget(input_otp)
            widget.setCurrentIndex(widget.currentIndex() + 1)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")
            if self.sock:
                self.sock.close()
            self.sock = None
            global_socket = None

class RegisterScreen(QDialog):
    def __init__(self, username="", email="", password=""):
        super(RegisterScreen, self).__init__()
        loadUi("Register.ui",self)
        self.sock = None
        self.check_and_connect()
        self.Password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.Password_2.setEchoMode(QtWidgets.QLineEdit.Password)
        self.loginButton.clicked.connect(self.gotologin)
        self.Register.clicked.connect(self.registerfunction)
        self.Username.setText(username)
        self.EmailRegister.setText(email)
        self.Password.setText(password)
        self.Password_2.setText(password)
        self.ErrorRegister.setText("")
        self.Username.textChanged.connect(self.check_fields)
        self.EmailRegister.textChanged.connect(self.check_fields)
        self.Password.textChanged.connect(self.check_fields)
        self.Password_2.textChanged.connect(self.check_fields)
        self.check_fields()

    def check_and_connect(self):
        global global_socket
        if global_socket is None:
            try:
                global_socket = socket.create_connection((HOST, PORT))
                self.sock = global_socket
                self.check_fields()
            except ConnectionRefusedError:
                QMessageBox.critical(self, "Connection Error", "Could not connect to the server.")
                self.Register.setEnabled(False)
                self.sock = None
            except Exception as e:
                QMessageBox.critical(self, "Network Error", f"An unexpected network error occurred: {e}")
                self.Register.setEnabled(False)
                self.sock = None
        else:
            self.sock = global_socket
            self.check_fields()

    def check_fields(self):
        can_enable_button = (bool(self.Username.text()) and bool(self.EmailRegister.text()) and
                                bool(self.Password.text()) and bool(self.Password_2.text()) and
                                self.sock is not None)
        self.Register.setEnabled(can_enable_button)
        if can_enable_button:
            self.Register.setStyleSheet("background-color: rgb(138, 44, 138);")
        else:
            self.Register.setStyleSheet("")

    def gotoRegistOTP(self):
        registerOTP = RegisterOTPScreen(self.Username.text(), self.EmailRegister.text(), self.Password.text())
        widget.addWidget(registerOTP)
        widget.setCurrentIndex(widget.currentIndex()+1)
        widget.setFixedSize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)

    def gotologin(self):
        login = LoginScreen()
        widget.addWidget(login)
        widget.setCurrentIndex(widget.currentIndex()+1)
        widget.setFixedSize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)

    def registerfunction(self):
        self.ErrorRegister.setText("")
        password = self.Password.text()
        
        if password != self.Password_2.text():
            self.ErrorRegister.setText("Passwords do not match!")
            return
            
        def validate_password(p):
            if not (10 <= len(p) <= 70): return "Password must be 10-70 characters."
            if not re.search('[A-Z]', p): return "Password needs an uppercase letter."
            if not re.search('[a-z]', p): return "Password needs a lowercase letter."
            if not re.search('[0-9]', p): return "Password needs a digit."
            if not re.search('[^a-zA-Z0-9]', p): return "Password needs a symbol."
            return None

        password_validation_error = validate_password(password)
        if password_validation_error:
            self.ErrorRegister.setText(password_validation_error)
            return

        global global_socket
        if not self.sock:
            QMessageBox.warning(self, "Connection Status", "Not connected to the server.")
            return

        username = self.Username.text()
        email = self.EmailRegister.text()
    
        try:
            self.sock.sendall(b"08register")
            
            self.sock.sendall(f"{len(username):02}{username}".encode())
            
            self.sock.sendall(f"{len(email):02}{email}".encode())
            

            hashed = bcrypt.hashpw(password.encode(), salt)
            self.sock.sendall(f"{len(hashed):02}".encode() + hashed)
            
            data = self.sock.recv(BUFF_SIZE)
            
            if not data:
                QMessageBox.critical(self, "Connection Error", "Server closed the connection.")
                return

            status, reply = parse_simple_response(data)
            if status == "error":
                self.ErrorRegister.setText(f"Registration Failed: {reply}")
            elif status == "success":
                self.gotoRegistOTP()
            else:
                self.ErrorRegister.setText(f"Unknown server response: {status}")

        except Exception as e:
            QMessageBox.critical(self, "Registration Error", f"An unexpected error occurred: {e}")
            if self.sock:
                self.sock.close()
            self.sock = None
            global_socket = None

class RegisterOTPScreen(QDialog):
    def __init__(self, username="", email="", password=""):
        super(RegisterOTPScreen, self).__init__()
        loadUi("RegisterOTP.ui",self)
        self.editEmail.clicked.connect(self.gotoregist)
        self.SubmitRegisterOTP.clicked.connect(self.registerOTPfunction)
        self.stored_username = username
        self.stored_email = email
        self.stored_password = password
        self.ErrorRegistOTP.setText("")
        self.sock = None
        self.check_and_connect()
        self.OTP.textChanged.connect(self.check_fields)
        self.check_fields()

    def check_and_connect(self):
        global global_socket
        if global_socket is None:
            QMessageBox.critical(self, "Connection Error", "No active connection to the server. Please go back to login screen.")
            self.SubmitRegisterOTP.setEnabled(False)
        else:
            self.sock = global_socket
            self.check_fields()

    def check_fields(self):
        is_otp_valid = len(self.OTP.text()) == 4 and self.OTP.text().isdigit()
        can_enable_button = is_otp_valid and self.sock is not None
        self.SubmitRegisterOTP.setEnabled(can_enable_button)
        if can_enable_button:
            self.SubmitRegisterOTP.setStyleSheet("background-color: rgb(138, 44, 138);")
        else:
            self.SubmitRegisterOTP.setStyleSheet("")

    def gotoregist(self):
        global global_socket
        if self.sock:
            try:
                self.sock.close()
            except Exception as e:
                print(f"Error closing socket on navigating back: {e}")
            self.sock = None
            global_socket = None
        regist = RegisterScreen(self.stored_username, self.stored_email, self.stored_password)
        widget.addWidget(regist)
        widget.setCurrentIndex(widget.currentIndex()+1)
        widget.setFixedSize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)

    def gotoCreated(self):
        created = CreatedAccount()
        widget.addWidget(created)
        widget.setCurrentIndex(widget.currentIndex()+1)
        widget.setFixedSize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)

    def registerOTPfunction(self):
        self.ErrorRegistOTP.setText("")
        otp = self.OTP.text()
        if not (len(otp) == 4 and otp.isdigit()):
            self.ErrorRegistOTP.setText("OTP must be 4 digits!")
            return

        global global_socket, global_user_obj
        if not self.sock:
            QMessageBox.warning(self, "Connection Status", "Not connected to the server.")
            return

        try:
            print("\n--- CLIENT LOG ---")
            print("[CLIENT] STEP 1: Sending OTP to server...")
            self.sock.sendall(otp.encode())
            print("[CLIENT] STEP 2: Waiting for server to validate OTP...")
            data = self.sock.recv(BUFF_SIZE)
            print("[CLIENT] STEP 3: Received OTP response from server.")
            
            if not data:
                QMessageBox.critical(self, "Connection Error", "Server closed the connection unexpectedly.")
                return
            
            status, reply = parse_simple_response(data)
            print(f"[CLIENT] Server response: Status={status}, Reply={reply}")

            if status == "success":
                print("[CLIENT] STEP 4: OTP was valid. Proceeding to publish keys.")
                global_user_obj = User(self.stored_username, 1000)
                global_user_obj.store_keys()
                new_user_pk_in_json = global_user_obj.dump_pk_to_json()
                
                server.set_key_bundle(self.sock, self.stored_username, new_user_pk_in_json)
                
                print("[CLIENT] STEP 9: Key bundle process finished. Moving to 'Created' screen.")
                self.gotoCreated()
            elif status == "error":
                self.ErrorRegistOTP.setText("OTP Invalid")
            else:
                self.ErrorRegistOTP.setText(f"Unknown response from server: {status}: {reply}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")
            if self.sock: self.sock.close()
            self.sock = None
            global_socket = None

class CreatedAccount(QDialog):
    def __init__(self):
        super(CreatedAccount, self).__init__()
        loadUi("RegisterOTPSukses.ui",self)
        self.Login.clicked.connect(self.gotologin)

    def gotologin(self):
        login = LoginScreen()
        widget.addWidget(login)
        widget.setCurrentIndex(widget.currentIndex()+1)
        widget.setFixedSize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)

class InputOTP(QDialog):
    def __init__(self, email=""):
        super(InputOTP, self).__init__()
        loadUi("ResetPasswordMasukOTP.ui",self)
        self.editEmailReset.clicked.connect(self.gotoReset)
        self.Submit.clicked.connect(self.submitOTPFunction)
        self.sock = None
        self.check_and_connect()
        self.ErrorResetOTP.setText("") 
        self.stored_email = email
        self.OTP.textChanged.connect(self.check_fields)
        self.check_fields()
    
    def check_and_connect(self):
        global global_socket
        if global_socket is None:
            QMessageBox.critical(self, "Connection Error", "No active connection to the server.")
            self.editEmailReset.setEnabled(False)
            self.Submit.setEnabled(False)
        else:
            self.sock = global_socket
            self.check_fields()

    def check_fields(self):
        is_otp_valid = len(self.OTP.text()) == 4 and self.OTP.text().isdigit()
        can_enable_button = is_otp_valid and self.sock is not None
        self.Submit.setEnabled(can_enable_button)
        if can_enable_button:
            self.Submit.setStyleSheet("background-color: rgb(138, 44, 138);")
        else:
            self.Submit.setStyleSheet("")

    def gotoReset(self):
        global global_socket
        if self.sock:
            try:
                self.sock.close()
            except Exception as e:
                print(f"Error closing socket on navigating back: {e}")
            self.sock = None
            global_socket = None
        reset = ForgotScreen(self.stored_email)
        widget.addWidget(reset)
        widget.setCurrentIndex(widget.currentIndex()+1)
        widget.setFixedSize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)

    def submitOTPFunction(self):
        self.ErrorResetOTP.setText("")
        otp = self.OTP.text()
        if len(otp) != 4 or not otp.isdigit():
            self.ErrorResetOTP.setText("OTP must be 4 digits!")
            return

        global global_socket
        if not self.sock:
            QMessageBox.warning(self, "Connection Status", "Not connected to the server.")
            return

        try:
            self.sock.sendall(otp.encode())
            data = self.sock.recv(BUFF_SIZE)
            if not data:
                QMessageBox.critical(self, "Connection Error", "Server closed the connection unexpectedly.")
                if self.sock: self.sock.close()
                self.sock = None
                global_socket = None
                return
            
            status, reply = parse_simple_response(data)
            if status == "success":
                self.gotoChangePass()
            elif status == "error":
                self.ErrorResetOTP.setText(reply)
            else:
                self.ErrorResetOTP.setText(f"Unknown response: {status}: {reply}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")
            if self.sock: self.sock.close()
            self.sock = None
            global_socket = None

    def gotoChangePass(self):
        Change = ChangePass()
        widget.addWidget(Change)
        widget.setCurrentIndex(widget.currentIndex()+1)
        widget.setFixedSize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)

class ChangePass(QDialog):
    def __init__(self):
        super(ChangePass, self).__init__()
        loadUi("ResetPasswordMasukPassword.ui",self)
        self.newPassword.setEchoMode(QtWidgets.QLineEdit.Password)
        self.confirmNewPassword.setEchoMode(QtWidgets.QLineEdit.Password)
        self.ResetPassword.clicked.connect(self.submitPassFunction)
        self.sock = None
        self.check_and_connect()
        self.ErrorResetPassword.setText("")
        self.newPassword.textChanged.connect(self.check_fields)
        self.confirmNewPassword.textChanged.connect(self.check_fields)
        self.check_fields()

    def check_and_connect(self):
        global global_socket
        if global_socket is None:
            try:
                global_socket = socket.create_connection((HOST, PORT))
                self.sock = global_socket
                self.check_fields()
            except ConnectionRefusedError:
                QMessageBox.critical(self, "Connection Error", "Could not connect to the server.")
                self.ResetPassword.setEnabled(False)
                self.sock = None
            except Exception as e:
                QMessageBox.critical(self, "Network Error", f"An unexpected network error occurred: {e}")
                self.ResetPassword.setEnabled(False)
                self.sock = None
        else:
            self.sock = global_socket
            self.check_fields()

    def check_fields(self):
        can_enable_button = bool(self.newPassword.text()) and bool(self.confirmNewPassword.text()) and self.sock is not None
        self.ResetPassword.setEnabled(can_enable_button)
        if can_enable_button:
            self.ResetPassword.setStyleSheet("background-color: rgb(138, 44, 138);")
        else:
            self.ResetPassword.setStyleSheet("")

    def gotoResets(self):
        reset = Resets()
        widget.addWidget(reset)
        widget.setCurrentIndex(widget.currentIndex()+1)
        widget.setFixedSize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)

    def submitPassFunction(self):
        def validate_password(password: str) -> str | None:
            if not (10 <= len(password) <= 70): return "Password must be between 10 and 70 characters long."
            if not re.search('[A-Z]', password): return "Password must contain at least one uppercase letter."
            if not re.search('[a-z]', password): return "Password must contain at least one lowercase letter."
            if not re.search('[0-9]', password): return "Password must contain at least one digit."
            if not re.search('[^a-zA-Z0-9]', password): return "Password must contain at least one symbol"
            return None
    
        global global_socket
        if not self.sock:
            QMessageBox.warning(self, "Connection Status", "Not connected to the server.")
            return

        newpassword = self.newPassword.text()
        if newpassword != self.confirmNewPassword.text():
            self.ErrorResetPassword.setText("Passwords do not match!")
            return

        password_validation_error = validate_password(newpassword)
        if password_validation_error:
            self.ErrorResetPassword.setText(password_validation_error)
            return
            
        hashed = bcrypt.hashpw(newpassword.encode(), salt)
        try:
            self.sock.sendall(hashed)
            data = self.sock.recv(BUFF_SIZE)
            if not data:
                QMessageBox.critical(self, "Connection Error", "Server closed the connection unexpectedly.")
                if self.sock: self.sock.close()
                self.sock = None
                global_socket = None
                return
            status, reply = parse_simple_response(data)
            if status == "success":
                self.gotoResets()
            elif status == "error":
                self.ErrorResetPassword.setText(reply)
            else:
                self.ErrorResetPassword.setText(f"Unknown response from server: {status}: {reply}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred during password reset: {e}")
            if self.sock: self.sock.close()
            self.sock = None
            global_socket = None
            
class Resets(QDialog):
    def __init__(self):
        super(Resets, self).__init__()
        loadUi("ResetPasswordMasukPasswordSukses.ui",self)
        self.Login.clicked.connect(self.gotologin)

    def gotologin(self):
        login = LoginScreen()
        widget.addWidget(login)
        widget.setCurrentIndex(widget.currentIndex()+1)
        widget.setFixedSize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)

app = QApplication(sys.argv)
widget = QtWidgets.QStackedWidget()

welcome = LoginScreen()
widget.addWidget(welcome)
widget.setFixedSize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)

widget.show()

try:
    sys.exit(app.exec_())
except Exception as e:
    print(f"Exiting due to error: {e}")