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
import sys

HOST = "127.0.0.1"   # server address
PORT = 1234          # server port
BUFF_SIZE  = 4 * 1024      # receive buffer size
salt = b'$2b$12$x9ZnzLMloa9lnOwnZNmMn.'
# data for testing
# username: zakyhermawan
# password: mypassword

def get_total_length(data):
    first_digit = ord(data[0]) - ord('0')
    assert(first_digit >=0 and first_digit <= 9)
    second_digit = ord(data[1]) - ord('0')
    assert(second_digit >=0 and second_digit <= 9)
    total_length = first_digit * 10 + second_digit
    return total_length

# format: status;message
# ex: "05error;19registration failed"
def parse_response(data):
    decoded_data = data.decode()
    lenStatus = get_total_length(decoded_data)
    status = decoded_data[2:lenStatus + 2]
    message = decoded_data[lenStatus + 2 + 2 + 1:]
    return (status, message)

def main() -> None:
    # create a TCP socket (IPv4, stream)
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
                        print("OTP Valid")
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
