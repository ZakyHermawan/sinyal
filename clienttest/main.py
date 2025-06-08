#!/usr/bin/env python3
"""
Simple TCP echo-client.

$ python3 client.py
> hello world
echo: hello world
> quit            # or Ctrl-D / Ctrl-C
"""
import bcrypt # type: ignore
import socket
import base64
HOST = "127.0.0.1"   # server address
PORT = 1234          # server port
BUFF_SIZE  = 100 * 1024      # receive buffer size
salt = b'$2b$12$x9ZnzLMloa9lnOwnZNmMn.'
# data for testing
# username: zakyhermawan
# password: mypassword

# username: Alice
# email: kagebunshinnojutsu01@gmail.com
# password: alicepassword

# username: Bob
# email: 13220022@std.stei.itb.ac.id
# password: bobpassword

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

AES_N_LEN = 16
AES_TAG_LEN = 16
EC_KEY_LEN = 32
EC_SIGN_LEN = 64

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

    total_length = first_digit * 10000 + second_digit * 1000 + third_digit * 100 + second_digit * 10 + first_digit
    return total_length

def parse_response(data):
    decoded_data = data.decode()
    lenStatus = get_total_length(decoded_data)
    status = decoded_data[2:lenStatus + 2]
    message = decoded_data[2 + lenStatus + 1 + 2:]
    return (status, message)

def parse_response_key_bundle(data):
    decoded_data = data.decode()
    lenStatus = get_total_length(decoded_data)
    status = decoded_data[2:lenStatus + 2]
    message = decoded_data[2 + lenStatus + 1 + 5:]
    return (status, message)

def empty_socket_buffer(sock: socket.socket):
    """
    Reads from a socket until the receive buffer is empty.
    Temporarily sets the socket to non-blocking mode.
    """
    print("[Helper] Attempting to empty socket buffer...")
    try:
        # 1. Set the socket to non-blocking mode
        sock.setblocking(False)
        
        while True:
            # 2. Try to receive data.
            # If there's data, it will be received and discarded.
            # If there's no data, it will raise a BlockingIOError.
            data = sock.recv(4096)
            if not data:
                # The other side has closed the connection.
                print("[Helper] Socket connection closed while emptying.")
                break
            print(f"[Helper] Discarded {len(data)} bytes of stale data.")

    except BlockingIOError:
        # This is the expected "error" when the buffer is empty.
        # It means "would block" if the socket were in blocking mode.
        print("[Helper] Buffer is now empty.")
        pass # We're done.
    
    except Exception as e:
        print(f"[Helper] An unexpected error occurred: {e}")

    finally:
        # 3. CRUCIAL: Always set the socket back to blocking mode
        # for normal operation afterwards.
        sock.setblocking(True)

class Server:
    def __init__(self):
        self.key_bundles = {}
        self.mq = deque()
        self.message_queues = defaultdict(deque)  # user ➜ deque of messages

    def set_key_bundle(self, username, key_bundle):
        with socket.create_connection((HOST, PORT)) as sock:
            # max length of the key bundle (in binary) should be under 99999 bytes
            sock.send(f'18publish public key'.encode())

            # receive server response, but do nothing
            data = sock.recv(BUFF_SIZE)
            if not data:
                print("Connection closed by server")
                return

            msg = f'{len(username):02}{username};{len(key_bundle):05}{key_bundle}'.encode()
            sock.send(msg)

            data = sock.recv(BUFF_SIZE)
            if not data:
                print("Connection closed by server")
                return
            
            # print("received message:", data.decode(errors="replace"))
            status, reply = parse_response(data)
            # print(f"received msg: {status}: {reply}")
            if status == "success":
                # self.key_bundles[username] = key_bundle # TODO: delete this
                print("Key bundle has been set to the server")
            elif status == "error":
                print(f"Key bundle failed to set to the server, reason: {reply}")
            else:
                print(f"Unknown response: {status}: {reply}")
        

    def get_key_bundle(self, username):
        # just give the key bundle if it already there
        if self.key_bundles.get(username):
            return self.key_bundles[username]
        with socket.create_connection((HOST, PORT)) as sock:
            sock.send(f'14get public key'.encode())

            # receive server response, but do nothing
            data = sock.recv(BUFF_SIZE)
            if not data:
                print("Connection closed by server")
                return
            
            # print("Xcvxcvxv")
            msg = f'{len(username):02}{username}'.encode()
            sock.send(msg)
            data = sock.recv(BUFF_SIZE)
            if not data:
                print("Connection closed by server")
                return
            
            # print("received message:", data.decode(errors="replace"))
            status, reply = parse_response_key_bundle(data)
            # print(f"received msg: {status} {reply}")
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
        print(f" [*] Waiting for a message on queue '{to}' for {timeout} second(s)...")

        # --- This polling loop replaces start_consuming() ---
        start_time = time.time()
        while time.time() - start_time < timeout:
            # process_data_events will wait for up to 0.1s for I/O.
            # If a message arrives, it will trigger the callback.
            connection.process_data_events(time_limit=0.1)

            # If the callback added a message to our queue, we can stop waiting.
            if self.mq:
                print(" [*] Message received, exiting wait loop.")
                break
        
        connection.close()
        print(" [*] Connection closed.")

        if self.mq:
            return True # A message was received and is in the queue.
        else:
            print(" [*] No message received within the timeout period.")
            return False # Timed out.
    
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

    def publish(self):
        return {
            'IK_p': self.IK_p,
            'SPK_p': self.SPK_p,
            'SPK_sig': self.SPK_sig,
            'OPKs_p': self.OPKs_p,
            'OPK_p': self.OPKs_p[0],  # Pick one OPK
        }
    
    def store_keys(self):
        public_bundle = self.dump_pk_to_json()
        private_bundle = self.dump_priv_to_json()

        public_filename = f"{self.name}_public_keys.txt"
        private_filename = f"{self.name}_private_keys.txt"

        # --- Storing the Public Keys ---
        print(f"Storing public key bundle to '{public_filename}'...")
        # Use 'with open' to automatically handle closing the file
        with open(public_filename, 'w') as f:
            # print(public_bundle.decode())
            f.write(public_bundle.decode())
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
                # json.load() reads from a file object, parses the JSON,
                # and returns the corresponding Python object.
                public_data = json.load(f)
                public_key_bundle = self.parse_pubkey_dict_to_dict(public_data)
                self.IK_p = public_key_bundle['IK_p']
                self.SPK_p = public_key_bundle['SPK_p']
                self.sig = public_key_bundle['SPK_sig']
                self.OPKs_p = public_key_bundle['OPKs_p']
                self.OPK_p = public_key_bundle['OPK_p']
            print(f"Successfully loaded data from '{public_filename}'")
        except FileNotFoundError:
            print(f"ERROR: File '{public_filename}' not found.")
        except json.JSONDecodeError:
            print(f"ERROR: Could not decode JSON from '{public_filename}'.")

        # --- Loading the Private Keys ---
        try:
            with open(private_filename, 'r') as f:
                private_data = json.load(f)
                private_key_bundle = self.parse_privkey_dict_to_dict(private_data)
                self.IK_s = private_key_bundle['IK_s']
                self.SPK_s = private_key_bundle['SPK_s']

                self.OPKs = private_key_bundle['OPKs']
                # print(f"lennn: {len(self.OPKs)}")
                # print(f"di open: {self.OPKs}")
            print(f"Successfully loaded data from '{private_filename}'")
        except FileNotFoundError:
            print(f"ERROR: File '{private_filename}' not found.")
        except json.JSONDecodeError:
            print(f"ERROR: Could not decode JSON from '{private_filename}'.")
            
        return public_data, private_data

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

    def get_key_bundle(self, server, user_name):
        if user_name in self.key_bundles and user_name in self.dr_keys:
            print('Already stored ' + user_name + ' locally, no need handshake again')
            return False

        server.get_key_bundle(user_name)
        self.key_bundles[user_name] = server.key_bundles[user_name]
        return True

    def initial_handshake(self, server, user_name):
        if self.get_key_bundle(server, user_name):
            # Generate Ephemeral Key
            sk = x25519.X25519PrivateKey.generate()
            pk = sk.public_key()

            self.key_bundles[user_name]['EK_s'] = sk
            self.key_bundles[user_name]['EK_p'] = pk

            # Select one available OPK from recipient
            opk_list = self.key_bundles[user_name].get('OPKs_p', [])
            if not opk_list:
                raise ValueError(f"No OPK available from {user_name}")
            self.key_bundles[user_name]['OPK_p'] = opk_list.pop(0)

    def x3dh_KDF(self, key_material: bytes) -> bytes:
        KDF_F = b'\xff' * 32
        KDF_LEN = 32
        KDF_SALT = b'\x00' * KDF_LEN
        km = KDF_F + key_material
        return HKDF(km, KDF_LEN, KDF_SALT, SHA256, 1)

    def generate_send_secret_key(self, user_name: str):
        key_bundle = self.key_bundles[user_name]

        # Perform X3DH DH computations
        DH_1 = self.IK_s.exchange(key_bundle['SPK_p'])
        DH_2 = key_bundle['EK_s'].exchange(key_bundle['IK_p'])
        DH_3 = key_bundle['EK_s'].exchange(key_bundle['SPK_p'])
        DH_4 = key_bundle['EK_s'].exchange(key_bundle['OPK_p'])

        # Final shared key (SK)
        # here, we also modify self.key_bundles[user_name]['SK'] as a side effect, assignment to a dictionary is actually a reference
        key_bundle['SK'] = self.x3dh_KDF(DH_1 + DH_2 + DH_3 + DH_4)
        return key_bundle['SK']

    def dump_privatekey(self, private_key, to_str=True):
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

        return json.dumps(published_dict).encode('utf-8')

    def dump_priv_to_json(self):
        print(f"self.IK_s: {self.IK_s}")
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
            # because OPKs is actually a tuple (priv, pub)
            published_dict['OPKs'].append((self.dump_privatekey(i[0]).hex(), self.dump_publickey(i[1]).hex()))

        return json.dumps(published_dict).encode('utf-8')

    def build_x3dh(self, server, to, ad):
        # Binary additional data
        b_ad = (json.dumps({
        'from': self.name,
        'to': to,
        'message': ad
        })).encode('utf-8')

        key_bundle = self.key_bundles[to]
        # 64 byte signature
        key_comb = self.dump_publickey(self.IK_p) + self.dump_publickey(key_bundle['EK_p']) + self.dump_publickey(key_bundle['OPK_p'])
        ik_priv = xeddsa.Priv(self.IK_s.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ))

        # Generate 64-byte random nonce
        nonce = os.urandom(64)

        # Sign the message
        signature = xeddsa.ed25519_priv_sign(ik_priv, key_comb + b_ad, nonce)
        print(f"{self.name} message signature: {signature}")
        print("data: ", key_comb + b_ad)

        # 16 byte aes nonce
        nonce = get_random_bytes(AES_N_LEN)
        cipher = AES.new(key_bundle['SK'], AES.MODE_GCM, nonce=nonce, mac_len=AES_TAG_LEN)
        # 32 + 32 + len(ad) byte cipher text
        ciphertext, tag = cipher.encrypt_and_digest(signature + self.dump_publickey(self.IK_p) + self.dump_publickey(key_bundle['IK_p']) + b_ad)

        # initial message: (32 + 32 +32) + 16 + 16 + 64 + 32 + 32 + len(ad)
        message = key_comb + nonce + tag + ciphertext
        server.send(to, message)

    def search_OPK_lst(self, opk_pub_bytes: bytes):
        """
        Given an OPK public key in raw bytes, find and return the corresponding secret key.
        Removes the matched OPK from the list to prevent reuse.
        """
        for i, (sk, pk) in enumerate(self.OPKs):
            pk_bytes = pk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            if pk_bytes == opk_pub_bytes:
                # Remove from OPK list (used once)
                self.OPKs.pop(i)
                self.OPKs_p.pop(i)
                return sk
        return None

    def recv_x3dh(self, server, is_blocking=False):
        # receive the hello message
        if is_blocking == True:
            server.blocking_recv(self.name)
        else:
            message_available = server.recv(self.name)
            if message_available == False:
                print("No incoming message!")
                return None
        message = server.pop_from_mq()
        if message == None:
            print("No new message!")
            return None
        # self.get_key_bundle(server, sender)

        # key_bundle = self.key_bundles[sender]

        IK_pa = message[:EC_KEY_LEN]
        EK_pa = message[EC_KEY_LEN:EC_KEY_LEN*2]
        OPK_pb = message[EC_KEY_LEN*2:EC_KEY_LEN*3]
        nonce = message[EC_KEY_LEN*3:EC_KEY_LEN*3+AES_N_LEN]
        tag = message[EC_KEY_LEN*3+AES_N_LEN:EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN]
        ciphertext = message[EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN:]

        sk = self.generate_recv_secret_key(IK_pa, EK_pa, OPK_pb)
        # print(f'{self.name} sk: {sk}')

        if sk is None:
            print("keks")
            return

        # key_bundle['SK'] = sk
        message = self.x3dh_decrypt_and_verify(sk, IK_pa, EK_pa, nonce, tag, ciphertext)

        # Get Ek_pa and plaintext ad
        return EK_pa, message

    def generate_recv_secret_key(self, IK_pa, EK_pa, OPK_pb):

        # Find corresponding secret OPK secret key
        # And remove the pair from the list
        OPK_sb = self.search_OPK_lst(OPK_pb)
        if OPK_sb is None:
            print("no opk")
            return

        IK_pa = x25519.X25519PublicKey.from_public_bytes(IK_pa)
        EK_pa = x25519.X25519PublicKey.from_public_bytes(EK_pa)

        DH_1 = self.SPK_s.exchange(IK_pa)
        DH_2 = self.IK_s.exchange(EK_pa)
        DH_3 = self.SPK_s.exchange(EK_pa)
        DH_4 = OPK_sb.exchange(EK_pa)

        # create SK
        return self.x3dh_KDF(DH_1 + DH_2 + DH_3 +DH_4)

    def x3dh_decrypt_and_verify(self, sk, IK_pa, EK_pa, nonce, tag, ciphertext):
        # Decrypt
        cipher = AES.new(sk, AES.MODE_GCM, nonce=nonce, mac_len=AES_TAG_LEN)
        p_all = None # initialize variable
        try:
            p_all = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            print('Unable to verify/decrypt ciphertext')
            return
        except Exception as e:
            print(f'Exception: {e}')
            return

        # Extract parts
        sign = p_all[:EC_SIGN_LEN]
        IK_pa_p = p_all[EC_SIGN_LEN:EC_SIGN_LEN+EC_KEY_LEN]
        IK_pb_p = p_all[EC_SIGN_LEN+EC_KEY_LEN:EC_SIGN_LEN+EC_KEY_LEN*2]
        ad = p_all[EC_SIGN_LEN+EC_KEY_LEN*2:]

        # Extract expected Bob identity key
        IK_pb = self.dump_publickey(self.IK_p)

        if IK_pa != IK_pa_p:
            print("Sender identity key mismatch!")
            return

        if IK_pb != IK_pb_p:
            print("Receiver identity key mismatch!")
            return

        print("Decryption and identity check passed!")
        print("Message:", json.loads(ad))
        return json.loads(ad)
    
    def receive_all_incoming_message(self, server):
        while True:
            incoming_message = self.recv_x3dh(server)
            if incoming_message == None:
                break

known_usernames = ['Alice', 'Bob'] # list of all users of the app (friendlist + user himself/herself)
server = None

def main() -> None:
    # create a TCP socket (IPv4, stream)
    server = Server()
    with socket.create_connection((HOST, PORT)) as sock:
        print(f"Connected to {HOST}:{PORT}")
        while True:
            print("Masukkan perintah: ", end='')
            perintah = input()
            if perintah == "login":
                sock.sendall(b"05login")
                print("Masukkan username: ", end='')
                username = input()
                username_length = len(username)

                print("Masukkan password: ", end='')
                password = input()
                
                print(f"salt: {salt}")
                hashed = bcrypt.hashpw(password.encode(), salt)
                msg = f"{username_length:02}".encode() + username.encode() + b";" + hashed

                user = User(username, 1000)
                user.load_keys()

                # get all public keys from other friendlist, and store it to server object
                for uname in known_usernames:
                    if uname != username:
                        user.get_key_bundle(server, uname)

                print("Trying to retrieve all incoming message when user is offline!")
                user.receive_all_incoming_message(server)

                # start chatting
                target_username = input("Insert username of people you want to chat with: ")
                
                # just to make no typo in target_username
                if target_username not in known_usernames:
                    print("Unknown target! App terminate")
                    return
                
                target_user = User(target_username, 1000)
                target_user.load_keys()

                # Always do these if you want to send the message 
                while True:
                    # always handshake and generate send secret key before sending
                    user.initial_handshake(server, target_username)
                    user.generate_send_secret_key(target_username)
                    msg = input(f"Message to send to {target_username}: ")
                    user.build_x3dh(server, target_username, msg)

                    print(f"{username} is trying to receive and decrypt {target_username}'s message...")

                    # wait until the user send message then decrypt, you need to use thread in real application
                    # this is only for simulation
                    result = user.recv_x3dh(server, is_blocking=True)
                    if result is not None:
                        ek_pa, ad = result
                        print("Bob successfully decrypted the message!")
                    else:
                        print("Bob failed to decrypt the message.")

            elif perintah == "register":
                sock.sendall(b"08register")
                print("Masukkan username: ", end='')
                username = input()
                username_length = len(username)

                print("Masukkan email: ", end='')
                email = input()
                email_length = len(email)


                print("Masukkan password: ", end='')
                password = input()
                hashed = bcrypt.hashpw(password.encode(), salt)
                msg = f"{username_length:02}".encode() + username.encode() + b";" + f"{email_length:02}".encode() + email.encode() + b';' + hashed

                print(f"msg: {msg}")
                sock.sendall(msg)
                data = sock.recv(BUFF_SIZE)
                if not data:
                    print("Connection closed by server")
                    return
                
                print("received message:", data.decode(errors="replace"))
                status, reply = parse_response(data)
                if status == "error":
                    print(f"Fail to register: {reply}")
                    continue
                elif status == "success":
                    print("Username and email are does not exist in database! now check email for OTP!")
                    otp = None
                    while True:
                        print("Masukkan kode OTP:", end='')
                        otp = input()
                        if len(otp) != 4:
                            print("OTP harus 4 digit!")
                        else:
                            break
                    sock.sendall(otp.encode())
                    data = sock.recv(BUFF_SIZE)
                    if not data:
                        print("Connection closed by server")
                        return
                    
                    print("received message:", data.decode(errors="replace"))
                    status, reply = parse_response(data)

                    print(f"received msg: {status}: {reply}")
                    if status == "success":
                        print("OTP Valid, User has been created!")
                        # assign new user to the dictionary, for messaging purpose
                        new_user = User(username, 1000)
                        new_user.store_keys()
                        new_user_pk_in_json = new_user.dump_pk_to_json()
                        server.set_key_bundle(username, new_user_pk_in_json)
                    elif status == "error":
                        print(f"OTP Invalid")
                    else:
                        print(f"Unknown response: {status}: {reply}")
                    continue

                else:
                    print(f"Unknown response: {status}: {reply}")


            elif perintah == "reset password":
                sock.sendall(b"14reset password")
                print("Masukkan email: ", end='')
                email = input()
                email_length = len(email)
                msg = f"{email_length:02}".encode() + email.encode()

                print(f"msg: {msg}")
                sock.sendall(msg)
                data = sock.recv(BUFF_SIZE)
                if not data:
                    print("Connection closed by server")
                    return
                
                print("received message:", data.decode(errors="replace"))
                status, reply = parse_response(data)
                if status != "success":
                    print(f"error: {reply}")
                    continue
                otp = None
                while True:
                    print("Masukkan 4 digit kode OTP: ", end='')
                    otp = input()
                    if len(otp) != 4:
                        print("OTP harus 4 digit!")
                    else:
                        break
                sock.sendall(otp.encode())

                data = sock.recv(BUFF_SIZE)
                if not data:
                    print("Connection closed by server")
                    return
                
                print("received message:", data.decode(errors="replace"))

                status, reply = parse_response(data)

                print(f"received msg: {status}: {reply}")
                if status == "success":
                    print("OTP Valid")
                    password_baru = input("Masukkan password baru: ")
                    hashed = bcrypt.hashpw(password_baru.encode(), salt)
                    print(f"hash password baru: {hashed.decode()}")
                    sock.sendall(hashed)

                    data = sock.recv(BUFF_SIZE)
                    if not data:
                        print("Connection closed by server")
                        return
                    print("received message:", data.decode(errors="replace"))

                elif status == "error":
                    print(f"OTP Invalid")
                else:
                    print(f"Unknown response: {status}: {reply}")
                continue
            else:
                print("Unrecognized command")
                continue

            print(f"msg: {msg}")
            sock.sendall(msg)
            data = sock.recv(BUFF_SIZE)
            if not data:
                print("Connection closed by server")
                return
            print("received message:", data.decode(errors="replace"))

if __name__ == "__main__":
    try:
        main()
        print("Bye!")
    except KeyboardInterrupt:
        print("\nInterrupted.")
