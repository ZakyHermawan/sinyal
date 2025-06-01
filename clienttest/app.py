import sys
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication, QWidget, QMessageBox, QInputDialog
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt # Import Qt for initial button state

import bcrypt
import socket
import re

HOST = "127.0.0.1"
PORT = 1234
BUFF_SIZE = 4 * 1024
salt = b'$2b$12$x9ZnzLMloa9lnOwnZNmMn.'
# data for testing
# username: zakyhermawan
# password: mypassword

# Global variable to hold the socket
global_socket = None

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

        # Connect text changed signals to the validation function
        self.Username.textChanged.connect(self.check_fields)
        self.Password.textChanged.connect(self.check_fields)

        # Initialize error label
        self.ErrorLogin.setText("") 

        # Call check_fields once to set initial state and button style
        self.check_fields()

    def check_and_connect(self):
        global global_socket # Declare global first
        if global_socket is None:
            try:
                global_socket = socket.create_connection((HOST, PORT))
                print(f"Connected to {HOST}:{PORT}")
                self.sock = global_socket
                # Only enable buttons if connection is successful
                self.registerButton.setEnabled(True)
                self.forgotPasswordButton.setEnabled(True)
                self.check_fields() # Re-check fields to enable login if already filled
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
            # If already connected, ensure buttons are enabled based on field content
            self.registerButton.setEnabled(True)
            self.forgotPasswordButton.setEnabled(True)
            self.check_fields()

    def check_fields(self):
        # Enable login button only if both username and password fields are not empty and socket is connected
        is_username_filled = bool(self.Username.text())
        is_password_filled = bool(self.Password.text())
        can_enable_button = is_username_filled and is_password_filled and self.sock is not None
        
        self.Login.setEnabled(can_enable_button)
        if can_enable_button:
            self.Login.setStyleSheet("background-color: rgb(138, 44, 138);")
        else:
            self.Login.setStyleSheet("") # Revert to default style when disabled


    def closeEvent(self, event):
        global global_socket # Declare global first
        if global_socket:
            global_socket.close()
            print("Global socket closed.")
            global_socket = None # Reset global_socket
        super().closeEvent(event)

    def loginfunction(self):
        global global_socket # Declare global first
        if not self.sock:
            QMessageBox.warning(self, "Connection Status", "Not connected to the server. Please try again or restart the application.")
            return

        username = self.Username.text()
        password = self.Password.text()

        try:
            self.sock.sendall(b"05login")
            username_length = len(username)
            
            print(f"saltfunc: {salt}")
            hashed = bcrypt.hashpw(password.encode(), salt)
            msg = f"{username_length:02}".encode() + username.encode() + b";" + hashed
        
            print(f"msg: {msg}")
            self.sock.sendall(msg)
            data = self.sock.recv(BUFF_SIZE)
            if not data:
                print("Connection closed by server")
                QMessageBox.critical(self, "Connection Error", "Server closed the connection unexpectedly.")
                self.sock.close()
                self.sock = None
                global_socket = None # Reset global_socket
                return
            print("received message:", data.decode(errors="replace"))
            status, reply = parse_response(data)
            if status == "success":
                self.ErrorLogin.setText("")
                self.gotoSuccess()
            else:
                self.ErrorLogin.setText("Invalid username or password")

        except BrokenPipeError:
            QMessageBox.critical(self, "Connection Error", "Connection to server lost. Please restart the application.")
            if self.sock: # Ensure self.sock is not None before trying to close it
                self.sock.close()
            self.sock = None
            global_socket = None # Reset global_socket
        except Exception as e:
            QMessageBox.critical(self, "Login Error", f"An unexpected error occurred during login: {e}")
            print(f"An unexpected error occurred: {e}")
            if self.sock:
                self.sock.close()
            self.sock = None
            global_socket = None # Reset global_socket


    def gotoregister(self):
        # Pass empty strings initially as there's no prior data
        register = RegisterScreen("", "", "")
        widget.addWidget(register)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def gotoforgot(self):
        forgot = ForgotScreen()
        widget.addWidget(forgot)
        widget.setCurrentIndex(widget.currentIndex() + 1)

    def gotoSuccess(self):
        success = LoggedScreen()
        widget.addWidget(success)
        widget.setCurrentIndex(widget.currentIndex() + 1)


class RegisterScreen(QDialog):
    # Add parameters to __init__ for pre-filling data
    def __init__(self, username="", email="", password=""):
        super(RegisterScreen, self).__init__()
        loadUi("Register.ui",self)
        self.sock = None
        self.check_and_connect()

        self.Password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.Password_2.setEchoMode(QtWidgets.QLineEdit.Password)
        self.loginButton.clicked.connect(self.gotologin)
        self.Register.clicked.connect(self.registerfunction)
        
        # Pre-fill the fields if data is provided
        self.Username.setText(username)
        self.EmailRegister.setText(email)
        self.Password.setText(password)
        self.Password_2.setText(password) # Assuming password confirmation is also pre-filled

        # Initialize ErrorRegister label text
        self.ErrorRegister.setText("")

        # Connect text changed signals to the validation function
        self.Username.textChanged.connect(self.check_fields)
        self.EmailRegister.textChanged.connect(self.check_fields)
        self.Password.textChanged.connect(self.check_fields)
        self.Password_2.textChanged.connect(self.check_fields)

        # Call once to set initial state and button style
        self.check_fields()

    def check_and_connect(self):
        global global_socket # Declare global first
        if global_socket is None:
            try:
                global_socket = socket.create_connection((HOST, PORT))
                print(f"Connected to {HOST}:{PORT}")
                self.sock = global_socket
                self.check_fields() # Re-check fields to enable register if already filled
            except ConnectionRefusedError:
                QMessageBox.critical(self, "Connection Error", "Could not connect to the server. Please ensure the server is running.")
                self.Register.setEnabled(False)
                self.sock = None
            except Exception as e:
                QMessageBox.critical(self, "Network Error", f"An unexpected network error occurred: {e}")
                self.Register.setEnabled(False)
                self.sock = None
        else:
            self.sock = global_socket
            self.check_fields() # If already connected, ensure button state is correct

    def check_fields(self):
        # Enable register button only if all fields are filled and socket is connected
        is_username_filled = bool(self.Username.text())
        is_email_filled = bool(self.EmailRegister.text())
        is_password_filled = bool(self.Password.text())
        is_confirm_password_filled = bool(self.Password_2.text())
        
        can_enable_button = (is_username_filled and is_email_filled and 
                             is_password_filled and is_confirm_password_filled and 
                             self.sock is not None)

        self.Register.setEnabled(can_enable_button)
        if can_enable_button:
            self.Register.setStyleSheet("background-color: rgb(138, 44, 138);")
        else:
            self.Register.setStyleSheet("") # Revert to default style when disabled

    def gotoRegistOTP(self):
        # Pass the current input values to RegisterOTPScreen
        registerOTP = RegisterOTPScreen(
            self.Username.text(),
            self.EmailRegister.text(),
            self.Password.text()
        )
        widget.addWidget(registerOTP)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def gotologin(self):
        login = LoginScreen()
        widget.addWidget(login)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def registerfunction(self):
        # Clear previous error messages
        self.ErrorRegister.setText("")

        def validate_password(password: str) -> str | None:
            # Criterion 1: Password length
            if not (10 <= len(password) <= 70):
                return "Password must be between 10 and 70 characters long."

            # Criterion 2: Contains at least one uppercase letter
            if not re.search('[A-Z]', password):
                return "Password must contain at least one uppercase letter."

            # Criterion 3: Contains at least one lowercase letter
            if not re.search('[a-z]', password):
                return "Password must contain at least one lowercase letter."

            # Criterion 4: Contains at least one digit
            if not re.search('[0-9]', password):
                return "Password must contain at least one digit."

            # Criterion 5: Contains at least one symbol
            if not re.search('[^a-zA-Z0-9]', password):
                return "Password must contain at least one symbol"

            return None
    
        global global_socket # Declare global first
        if not self.sock:
            QMessageBox.warning(self, "Connection Status", "Not connected to the server.")
            return

        username = self.Username.text()
        email = self.EmailRegister.text()
        password = self.Password.text()
        confirm_password = self.Password_2.text()

        if not username or not email or not password or not confirm_password:
            self.ErrorRegister.setText("All fields are required.")
            return

        if password != confirm_password:
            self.ErrorRegister.setText("Passwords do not match!")
            return

        password_validation_error = validate_password(password)
        if password_validation_error:
            self.ErrorRegister.setText(password_validation_error)
            return
            
        try:
            self.sock.sendall(b"08register")
            username_length = len(username)
            email_length = len(email)
            hashed = bcrypt.hashpw(password.encode(), salt)
            msg = f"{username_length:02}".encode() + username.encode() + b";" + f"{email_length:02}".encode() + email.encode() + b';' + hashed

            print(f"msg: {msg}")
            self.sock.sendall(msg)
            data = self.sock.recv(BUFF_SIZE)
            if not data:
                print("Connection closed by server")
                QMessageBox.critical(self, "Connection Error", "Server closed the connection unexpectedly.")
                if self.sock: self.sock.close()
                self.sock = None
                global_socket = None # Reset global_socket
                return
            
            print("received message:", data.decode(errors="replace"))
            status, reply = parse_response(data)
            if status == "error":
                self.ErrorRegister.setText(f"Registration Failed: {reply}")
            elif status == "success":
                self.gotoRegistOTP()
            else:
                self.ErrorRegister.setText(f"Unknown response from server: {status}: {reply}")
        except BrokenPipeError:
            QMessageBox.critical(self, "Connection Error", "Connection to server lost. Please restart the application.")
            if self.sock: self.sock.close()
            self.sock = None
            global_socket = None # Reset global_socket
        except Exception as e:
            QMessageBox.critical(self, "Registration Error", f"An unexpected error occurred during registration: {e}")
            print(f"An unexpected error occurred: {e}")
            if self.sock:
                self.sock.close()
            self.sock = None
            global_socket = None # Reset global_socket


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

        # Connect text changed signal to the validation function
        self.Email.textChanged.connect(self.check_fields)

        # Call once to set initial state and button style
        self.check_fields()

    def check_and_connect(self):
        global global_socket # Declare global first
        if global_socket is None:
            try:
                global_socket = socket.create_connection((HOST, PORT))
                print(f"Connected to {HOST}:{PORT}")
                self.sock = global_socket
                self.check_fields() # Re-check fields to enable sendOTP if already filled
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
            self.check_fields() # If already connected, ensure button state is correct

    def check_fields(self):
        # Enable sendOTP button only if email field is not empty and socket is connected
        is_email_filled = bool(self.Email.text())
        can_enable_button = is_email_filled and self.sock is not None
        
        self.sendOTP.setEnabled(can_enable_button)
        if can_enable_button:
            self.sendOTP.setStyleSheet("background-color: rgb(138, 44, 138);")
        else:
            self.sendOTP.setStyleSheet("") # Revert to default style when disabled

    def gotologin(self):
        login = LoginScreen()
        widget.addWidget(login)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def OTPFunction(self):
        # Clear previous error messages
        self.ErrorEmailReset.setText("")

        global global_socket # Declare global first
        if not self.sock:
            QMessageBox.warning(self, "Connection Status", "Not connected to the server.")
            return

        email = self.Email.text()
        if not email:
            self.ErrorEmailReset.setText("Please enter your email!")
            return

        try:
            self.sock.sendall(b"14reset password")
            email_length = len(email)
            msg = f"{email_length:02}".encode() + email.encode()

            print(f"msg: {msg}")
            self.sock.sendall(msg)
            data = self.sock.recv(BUFF_SIZE)
            if not data:
                QMessageBox.critical(self, "Connection Error", "Server closed the connection unexpectedly.")
                if self.sock: self.sock.close()
                self.sock = None
                global_socket = None # Reset global_socket
                return
            
            print("received message:", data.decode(errors="replace"))
            status, reply = parse_response(data)
            if status != "success":
                self.ErrorEmailReset.setText(f"Error sending OTP: {reply}")
                return
            
            # Pass the email to InputOTP screen
            input_otp = InputOTP(email)
            widget.addWidget(input_otp)
            widget.setCurrentIndex(widget.currentIndex() + 1)
            
        except BrokenPipeError:
            QMessageBox.critical(self, "Connection Error", "Connection to server lost. Please restart the application.")
            if self.sock: self.sock.close()
            self.sock = None
            global_socket = None # Reset global_socket
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred during password reset: {e}")
            print(f"An unexpected error occurred: {e}")
            if self.sock:
                self.sock.close()
            self.sock = None
            global_socket = None # Reset global_socket

class LoggedScreen(QDialog):
    def __init__(self):
        super(LoggedScreen, self).__init__()
        loadUi("LoginSukses.ui",self)
        self.LogOut.clicked.connect(self.gotologin)

    def gotologin(self):
        login = LoginScreen()
        widget.addWidget(login)
        widget.setCurrentIndex(widget.currentIndex()+1)

class RegisterOTPScreen(QDialog):
    # Add parameters to __init__ to receive data from RegisterScreen
    def __init__(self, username="", email="", password=""):
        super(RegisterOTPScreen, self).__init__()
        loadUi("RegisterOTP.ui",self)
        self.editEmail.clicked.connect(self.gotoregist)
        self.SubmitRegisterOTP.clicked.connect(self.registerOTPfunction)

        # Store the received data
        self.stored_username = username
        self.stored_email = email
        self.stored_password = password

        # Initialize ErrorRegistOTP label text
        self.ErrorRegistOTP.setText("")

        self.sock = None
        self.check_and_connect()

        # Connect text changed signal to the validation function
        self.OTP.textChanged.connect(self.check_fields)

        # Call once to set initial state and button style
        self.check_fields()

    def check_and_connect(self):
        global global_socket # Declare global first
        if global_socket is None:
            QMessageBox.critical(self, "Connection Error", "No active connection to the server. Please go back to login screen.")
            self.SubmitRegisterOTP.setEnabled(False) # Disable submit if not connected
        else:
            self.sock = global_socket
            self.check_fields() # Ensure button state is correct if already connected

    def check_fields(self):
        # Enable submit button only if OTP field is 4 digits and socket is connected
        is_otp_valid = len(self.OTP.text()) == 4 and self.OTP.text().isdigit()
        can_enable_button = is_otp_valid and self.sock is not None
        
        self.SubmitRegisterOTP.setEnabled(can_enable_button)
        if can_enable_button:
            self.SubmitRegisterOTP.setStyleSheet("background-color: rgb(138, 44, 138);")
        else:
            self.SubmitRegisterOTP.setStyleSheet("") # Revert to default style when disabled

    def gotoregist(self):
        global global_socket
        if self.sock:
            try:
                self.sock.close()
                print("Socket closed when going back from OTP screen to Register screen.")
            except Exception as e:
                print(f"Error closing socket on navigating back: {e}")
            self.sock = None
            global_socket = None

        # Pass the stored data back to the RegisterScreen
        regist = RegisterScreen(
            self.stored_username,
            self.stored_email,
            self.stored_password
        )
        widget.addWidget(regist)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def gotoCreated(self):
        created = CreatedAccount()
        widget.addWidget(created)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def registerOTPfunction(self):
        # Clear previous error messages
        self.ErrorRegistOTP.setText("")

        otp = self.OTP.text()
        if len(otp) != 4 or not otp.isdigit():
            self.ErrorRegistOTP.setText("OTP must be 4 digits!")
            return

        global global_socket # Declare global first
        if not self.sock:
            QMessageBox.warning(self, "Connection Status", "Not connected to the server. Please restart the application.")
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
            
            print("received message:", data.decode(errors="replace"))
            status, reply = parse_response(data)
            print(f"received msg: {status}: {reply}")
            if status == "success":
                self.gotoCreated()
            elif status == "error":
                self.ErrorRegistOTP.setText("OTP Invalid")
            else:
                self.ErrorRegistOTP.setText(f"Unknown response from server: {status}: {reply}")
        except BrokenPipeError:
            QMessageBox.critical(self, "Connection Error", "Connection to server lost. Please restart the application.")
            if self.sock: self.sock.close()
            self.sock = None
            global_socket = None
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred during OTP verification: {e}")
            print(f"An unexpected error occurred: {e}")
            if self.sock:
                self.sock.close()
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

# InputOTP Screen (for Password Reset)
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
        
        # Connect text changed signal to the validation function
        self.OTP.textChanged.connect(self.check_fields)

        # Call once to set initial state and button style
        self.check_fields()
    
    def check_and_connect(self):
        global global_socket
        if global_socket is None:
            QMessageBox.critical(self, "Connection Error", "No active connection to the server. Please go back and try again.")
            self.editEmailReset.setEnabled(False)
            self.Submit.setEnabled(False) # Disable Submit if not connected
        else:
            self.sock = global_socket
            self.check_fields() # Ensure button state is correct if already connected

    def check_fields(self):
        # Enable submit button only if OTP field is 4 digits and socket is connected
        is_otp_valid = len(self.OTP.text()) == 4 and self.OTP.text().isdigit()
        can_enable_button = is_otp_valid and self.sock is not None
        
        self.Submit.setEnabled(can_enable_button)
        if can_enable_button:
            self.Submit.setStyleSheet("background-color: rgb(138, 44, 138);")
        else:
            self.Submit.setStyleSheet("") # Revert to default style when disabled

    def gotoReset(self):
        global global_socket
        # Close the current socket before going back
        if self.sock:
            try:
                self.sock.close()
                print("Socket closed when going back from InputOTP screen to Forgot screen.")
            except Exception as e:
                print(f"Error closing socket on navigating back from InputOTP: {e}")
            self.sock = None
            global_socket = None

        # Navigate back to ForgotScreen, passing the stored email
        reset = ForgotScreen(self.stored_email)
        widget.addWidget(reset)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def submitOTPFunction(self):
        # Clear previous error messages
        self.ErrorResetOTP.setText("")

        otp = self.OTP.text()
        if len(otp) != 4 or not otp.isdigit():
            self.ErrorResetOTP.setText("OTP must be 4 digits!")
            return

        global global_socket
        if not self.sock:
            QMessageBox.warning(self, "Connection Status", "Not connected to the server. Please restart.")
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
            
            print("received message:", data.decode(errors="replace"))
            status, reply = parse_response(data)

            if status == "success":
                self.gotoChangePass()
            elif status == "error":
                self.ErrorResetOTP.setText(reply)
            else:
                self.ErrorResetOTP.setText(f"Unknown response: {status}: {reply}")
        except BrokenPipeError:
            QMessageBox.critical(self, "Connection Error", "Connection to server lost. Please restart the application.")
            if self.sock: self.sock.close()
            self.sock = None
            global_socket = None
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred during OTP verification: {e}")
            print(f"An unexpected error occurred: {e}")
            if self.sock:
                self.sock.close()
            self.sock = None
            global_socket = None

    def gotoChangePass(self):
        Change = ChangePass()
        widget.addWidget(Change)
        widget.setCurrentIndex(widget.currentIndex()+1)

class ChangePass(QDialog):
    def __init__(self):
        super(ChangePass, self).__init__()
        loadUi("ResetPasswordMasukPassword.ui",self)
        self.newPassword.setEchoMode(QtWidgets.QLineEdit.Password)
        self.confirmNewPassword.setEchoMode(QtWidgets.QLineEdit.Password)
        self.ResetPassword.clicked.connect(self.submitPassFunction)
        
        self.sock = None
        self.check_and_connect()

        self.ErrorResetPassword.setText("") # Initialize error label

        # Connect text changed signals to the validation function
        self.newPassword.textChanged.connect(self.check_fields)
        self.confirmNewPassword.textChanged.connect(self.check_fields)

        # Call once to set initial state and button style
        self.check_fields()

    def check_and_connect(self):
        global global_socket # Declare global first
        if global_socket is None:
            try:
                global_socket = socket.create_connection((HOST, PORT))
                print(f"Connected to {HOST}:{PORT}")
                self.sock = global_socket
                self.check_fields() # Re-check fields to enable ResetPassword if already filled
            except ConnectionRefusedError:
                QMessageBox.critical(self, "Connection Error", "Could not connect to the server. Please ensure the server is running.")
                self.ResetPassword.setEnabled(False)
                self.sock = None
            except Exception as e:
                QMessageBox.critical(self, "Network Error", f"An unexpected network error occurred: {e}")
                self.ResetPassword.setEnabled(False)
                self.sock = None
        else:
            self.sock = global_socket
            self.check_fields() # If already connected, ensure button state is correct

    def check_fields(self):
        # Enable ResetPassword button only if both new password fields are not empty and socket is connected
        is_new_password_filled = bool(self.newPassword.text())
        is_confirm_new_password_filled = bool(self.confirmNewPassword.text())
        can_enable_button = is_new_password_filled and is_confirm_new_password_filled and self.sock is not None
        
        self.ResetPassword.setEnabled(can_enable_button)
        if can_enable_button:
            self.ResetPassword.setStyleSheet("background-color: rgb(138, 44, 138);")
        else:
            self.ResetPassword.setStyleSheet("") # Revert to default style when disabled

    def gotoResets(self):
        reset = Resets()
        widget.addWidget(reset)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def submitPassFunction(self):
        def validate_password(password: str) -> str | None:
            # Criterion 1: Password length
            if not (10 <= len(password) <= 70):
                return "Password must be between 10 and 70 characters long."

            # Criterion 2: Contains at least one uppercase letter
            if not re.search('[A-Z]', password):
                return "Password must contain at least one uppercase letter."

            # Criterion 3: Contains at least one lowercase letter
            if not re.search('[a-z]', password):
                return "Password must contain at least one lowercase letter."

            # Criterion 4: Contains at least one digit
            if not re.search('[0-9]', password):
                return "Password must contain at least one digit."

            # Criterion 5: Contains at least one symbol
            if not re.search('[^a-zA-Z0-9]', password):
                return "Password must contain at least one symbol"

            return None
    
        global global_socket # Declare global first
        if not self.sock:
            QMessageBox.warning(self, "Connection Status", "Not connected to the server.")
            return

        newpassword = self.newPassword.text()
        confirm_password = self.confirmNewPassword.text()

        if newpassword != confirm_password:
            self.ErrorResetPassword.setText("Passwords do not match!")
            return

        password_validation_error = validate_password(newpassword)
        if password_validation_error:
            self.ErrorResetPassword.setText(password_validation_error)
            return
            
        hashed = bcrypt.hashpw(newpassword.encode(), salt)
        print(f"hash password baru: {hashed.decode()}")
        try:
            self.sock.sendall(hashed)

            data = self.sock.recv(BUFF_SIZE)
            if not data:
                print("Connection closed by server")
                QMessageBox.critical(self, "Connection Error", "Server closed the connection unexpectedly.")
                if self.sock: self.sock.close()
                self.sock = None
                global_socket = None
                return
            print("received message:", data.decode(errors="replace"))
            status, reply = parse_response(data)
            print(f"received msg: {status}: {reply}")
            if status == "success":
                self.gotoResets()
            elif status == "error":
                self.ErrorResetPassword.setText(reply)
            else:
                self.ErrorResetPassword.setText(f"Unknown response from server: {status}: {reply}")
        except BrokenPipeError:
            QMessageBox.critical(self, "Connection Error", "Connection to server lost. Please restart the application.")
            if self.sock: self.sock.close()
            self.sock = None
            global_socket = None
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred during password reset: {e}")
            print(f"An unexpected error occurred: {e}")
            if self.sock:
                self.sock.close()
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


def get_total_length(data):
    first_digit = ord(data[0]) - ord('0')
    assert(first_digit >=0 and first_digit <= 9)
    second_digit = ord(data[1]) - ord('0')
    assert(second_digit >=0 and second_digit <= 9)
    total_length = first_digit * 10 + second_digit
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
        return (status, "Invalid response format: missing semicolon or message length")

    message_len_start_index = 2 + len_status + 1
    if len(decoded_data) < message_len_start_index + 2:
        return (status, "Response too short for message length")

    len_message_str = decoded_data[message_len_start_index : message_len_start_index + 2]
    try:
        len_message = int(len_message_str)
    except ValueError:
        return (status, "Invalid response format: message length not an integer")

    message_start_index = message_len_start_index + 2
    if len(decoded_data) < message_start_index + len_message:
        return (status, "Response too short for message content")

    message = decoded_data[message_start_index : message_start_index + len_message]
    
    return (status, message)


app = QApplication(sys.argv)
widget = QtWidgets.QStackedWidget()

# When initializing LoginScreen, it doesn't need to pass any data for registration
welcome = LoginScreen()
widget.addWidget(welcome)

widget.setFixedHeight(520)
widget.setFixedWidth(480)
widget.show()

try:
    sys.exit(app.exec_())
except Exception as e:
    print(f"Exiting due to error: {e}")
