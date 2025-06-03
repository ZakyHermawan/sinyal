from cryptography.hazmat.primitives.asymmetric import x25519
import os
import xeddsa
from cryptography.hazmat.primitives import serialization
import json

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256


from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

from collections import defaultdict, deque

AES_N_LEN = 16
AES_TAG_LEN = 16
EC_KEY_LEN = 32
EC_SIGN_LEN = 64

import base64

def decodeB64Str(b64_str: str) -> bytes:
    return base64.b64decode(b64_str)

class Server:
    def __init__(self):
        self.key_bundles = {}
        self.message_queues = defaultdict(deque)  # user ➜ deque of messages

    def set_key_bundle(self, username, key_bundle):
        self.key_bundles[username] = key_bundle
    
    def get_key_bundle(self, username):
        return self.key_bundles[username]

    def send(self, to: str, message: bytes, sender: str = None):
        """
        Simulate sending a message to a user.
        Optionally track the sender.
        """
        print(f"\n[Server] Delivering message to {to} from {sender}\n")
        self.message_queues[to].append((sender, message))

    def recv(self, to: str):
        """
        Simulate receiving a message for a user.
        Returns (sender, message) or (None, None) if empty.
        """
        if self.message_queues[to]:
            return self.message_queues[to].popleft()
        return None, None

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

    def get_key_bundle(self, server, user_name):
        if user_name in self.key_bundles and user_name in self.dr_keys:
            print('Already stored ' + user_name + ' locally, no need handshake again')
            return False

        self.key_bundles[user_name] = server.get_key_bundle(user_name)
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

    def build_x3dh_hello(self, server, to, ad):
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
        server.send(to, message, sender=self.name)

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

    def recv_x3dh_hello_message(self, server):
        # receive the hello message
        sender, recv = server.recv(self.name)
        self.get_key_bundle(server, sender)

        key_bundle = self.key_bundles[sender]

        IK_pa = recv[:EC_KEY_LEN]
        EK_pa = recv[EC_KEY_LEN:EC_KEY_LEN*2]
        OPK_pb = recv[EC_KEY_LEN*2:EC_KEY_LEN*3]
        nonce = recv[EC_KEY_LEN*3:EC_KEY_LEN*3+AES_N_LEN]
        tag = recv[EC_KEY_LEN*3+AES_N_LEN:EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN]
        ciphertext = recv[EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN:]

        sk = self.generate_recv_secret_key(IK_pa, EK_pa, OPK_pb)
        print(f'{self.name} sk: {sk}')

        if sk is None:
            return

        key_bundle['SK'] = sk
        message = self.x3dh_decrypt_and_verify(key_bundle, IK_pa, EK_pa, nonce, tag, ciphertext)

        # Get Ek_pa and plaintext ad
        return EK_pa, message

    def generate_recv_secret_key(self, IK_pa, EK_pa, OPK_pb):

        # Find corresponding secret OPK secret key
        # And remove the pair from the list
        OPK_sb = self.search_OPK_lst(OPK_pb)
        if OPK_sb is None:
            return

        IK_pa = x25519.X25519PublicKey.from_public_bytes(IK_pa)
        EK_pa = x25519.X25519PublicKey.from_public_bytes(EK_pa)

        DH_1 = self.SPK_s.exchange(IK_pa)
        DH_2 = self.IK_s.exchange(EK_pa)
        DH_3 = self.SPK_s.exchange(EK_pa)
        DH_4 = OPK_sb.exchange(EK_pa)

        # create SK
        return self.x3dh_KDF(DH_1 + DH_2 + DH_3 +DH_4)

    def x3dh_decrypt_and_verify(self, key_bundle, IK_pa, EK_pa, nonce, tag, ciphertext):
        # Decrypt
        cipher = AES.new(key_bundle['SK'], AES.MODE_GCM, nonce=nonce, mac_len=AES_TAG_LEN)
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

if __name__ == '__main__':
    server = Server()
    alice = User("Alice", 1000) # generate private-public keys
    bob = User("Bob", 1000) # generate private-public keys

    print("Alice and bob generate private-public keys!")
    public_keys1 = alice.publish()
    public_keys2 = bob.publish()

    server.set_key_bundle(alice.name, public_keys1)
    server.set_key_bundle(bob.name, public_keys2)
    print("Alice and bob publish public keys to server!")
    
    alice.get_key_bundle(server, "Bob")
    print("Alice receive Bob's public keys!")
    bob.get_key_bundle(server, "Alice")
    print("Bob receive Alice's public keys!")
    bob_key_bundles = alice.key_bundles["Bob"]
    alice_key_bundles = bob.key_bundles["Alice"]

    print("Is Alice receive correct Bob's public key ?", bob_key_bundles == public_keys2)
    print("Is Bob receive correct Alice's public key ?", alice_key_bundles == public_keys1)

    while True:
        print()
        print()
        print("Alice trying to send message to bob, initial handshake!")
        alice.initial_handshake(server, 'Bob')
        alice_sk = alice.generate_send_secret_key('Bob')
        msg = input("Message to send to Bob: ")
        alice.build_x3dh_hello(server, 'Bob', msg)

        print("Bob is trying to receive and decrypt Alice's message...")
        result = bob.recv_x3dh_hello_message(server)

        if result is not None:
            ek_pa, ad = result
            print("Bob successfully decrypted the message!")
        else:
            print("Bob failed to decrypt the message.")

        print()
        print()

        print("Bob is trying to send message to bob, initial handshake!")
        bob.initial_handshake(server, 'Alice')
        bob.generate_send_secret_key('Alice')  # Add this line

        msg = input("Message to send to Alice: ")
        bob.build_x3dh_hello(server, 'Alice', msg)
        print("Bob is trying to receive and decrypt Alice's message...")
        result = alice.recv_x3dh_hello_message(server)
        if result is not None:
            ek_pa, ad = result
            print("Alice successfully decrypted the message!")
        else:
            print("Alice failed to decrypt the message.")
