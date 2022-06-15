import rsa
import string, random, socket, pickle
import CERT
import GLOBALS
from datetime import date
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def sign_using_private_key(message, private_key):
    message = message.encode('utf8')
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_using_public_key(signature, message, public_key):
    message = message.encode('utf8')
    return public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def rand_str(chars=string.ascii_uppercase + string.digits, len=10):
    return ''.join(random.choice(chars) for _ in range(len))


# server want to become CA

# get list of CA

# ASK FROM SPECIFIC CA (TO BECAME ca)

# sign to another CA


class CA:
    def __init__(self, name, HOST, PORT, CA_FLAG=True):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.name = name
        self.HOST = HOST
        self.PORT = PORT
        self.signer_name = "BLa"
        self.signer_IP = ""
        self.signer_IP = ""
        self.signer_PORT = ""
        self.signature = "bka"
        self.msg = "bka"
        self.start_date = ""
        self.end_date = ""
        self.CA_FLAG = CA_FLAG

    def print(self):
        print(self.name, self.signer_name, self.signature, self.msg)

    def import_cert(self):
        return self.name, self.signer_name, self.signature, self.msg

    def add_to_revoke_list(self, cert):
        # the ip and the port of the ca_tree server
        HOST = GLOBALS.CA_SERVER_IP
        PORT = GLOBALS.CA_SERVER_PORT
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, int(PORT)))
            s.sendall(b"add cert to revoke")
            data = s.recv(1024)
            # CA1.signer_name, CA1.signature, CA1.msg= pickle.loads(data)
            print(data)
            data = data.decode('utf-8')
            if data != "Please send me your cert":
                print("error")
            cert = CERT.cert(self.name, self.HOST, self.PORT, self.signer_IP, self.signer_PORT, self.msg,
                             self.signer_name, self.signature,
                             str(self.public_key), self.start_date, self.end_date, self.CA_FLAG)
            cert.print()
            cert_to_send = pickle.dumps(cert)
            s.sendall(cert_to_send)
            s.recv(1024)
            #data = data.decode('utf-8')
            return cert

    def sign_to_another_ca(self):
        # socket
        # name OF CA THAT YOU SIGN
        # msg = rand_str()
        msg = "reut"
        signature = sign_using_private_key(msg, self.private_key)
        name_of_ca = self.name
        start_date = date.today()

        end_date = date(start_date.year + 1, start_date.month, start_date.day)
        print(name_of_ca, self.HOST, self.PORT, signature, msg, start_date, end_date)
        return name_of_ca, self.HOST, self.PORT, signature, msg, start_date, end_date

    def request_public_key_from_ca(self, signer_ip, signer_port):
        HOST = signer_ip
        PORT = signer_port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, int(PORT)))
            s.sendall(b"request_public_key")
            data = s.recv(1024)
            key = load_pem_public_key(data)

            return key

    def update_in_ca_tree(self):
        # the ip and the port of the ca_tree server
        HOST = GLOBALS.CA_SERVER_IP
        PORT = GLOBALS.CA_SERVER_PORT
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, int(PORT)))
            s.sendall(b"update data")
            data = s.recv(1024)
            # CA1.signer_name, CA1.signature, CA1.msg= pickle.loads(data)
            print(data)
            data = data.decode('utf-8')
            if data != "Please send me your cert":
                print("error")
            cert = CERT.cert(self.name, self.HOST, self.PORT, self.signer_IP, self.signer_PORT, self.msg,
                             self.signer_name, self.signature,
                             str(self.public_key), self.start_date, self.end_date, self.CA_FLAG)
            cert.print()
            cert_to_send = pickle.dumps(cert)
            s.sendall(cert_to_send)
            s.recv(1024)
            #data = data.decode('utf-8')
            return cert

    def get_all_valid_ca(self):
        HOST = GLOBALS.CA_SERVER_IP
        PORT = GLOBALS.CA_SERVER_PORT
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, int(PORT)))
            s.sendall(b"get all ca's")
            data = s.recv(20000)
            CA_LIST = pickle.loads(data)
            print(CA_LIST)
            return CA_LIST

    def get_revocation_list(self):
        SERVER_HOST = GLOBALS.CA_SERVER_IP
        SERVER_PORT = GLOBALS.CA_SERVER_PORT
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, int(SERVER_PORT)))
            s.sendall(b"get revocation list")
            data = s.recv(20000)
            revocation_list = pickle.loads(data)
            print(revocation_list)
            return revocation_list

    def check_if_cert_in_revocation_list(self, cert=None):
        # the ip and the port of the ca_tree server
        HOST = GLOBALS.CA_SERVER_IP
        PORT = GLOBALS.CA_SERVER_PORT

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, int(PORT)))
            s.sendall(b"check if cert is valid")
            data = s.recv(1024)
            data = data.decode('utf-8')
            if data != "Please send me the cert":
                print("error")
            if cert == None:
                pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                cert = CERT.cert(self.name, self.HOST, self.PORT, self.signer_IP, self.signer_PORT, self.msg,
                                 self.signer_name, self.signature,
                                 pem, self.start_date, self.end_date, self.CA_FLAG)
            else:
                cert = cert
            cert.print()
            cert_to_send = pickle.dumps(cert)
            s.sendall(cert_to_send)
            ans = s.recv(1024)
            # CA1.signer_name, CA1.signature, CA1.msg= pickle.loads(data)
            print(data)
            data = data.decode('utf-8')
            if data == "The cert is valid (signature and date)":
                return True
            else:
                return False

    def request_signature_from_ca(self, signer_ip, signer_port):
        HOST = signer_ip
        PORT = signer_port

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, int(PORT)))
            s.sendall(b"request_cert")
            data = s.recv(20000)
            # CA1.signer_name, CA1.signature, CA1.msg= pickle.loads(data)
            print(data)
            data = data.decode('utf-8').split()

            self.signer_name, self.signer_IP, self.signer_PORT, self.msg, self.start_date, self.end_date = data[0], \
                                                                                                           data[1], \
                                                                                                           data[2], \
                                                                                                           data[3], \
                                                                                                           data[4], \
                                                                                                           data[5]

            s.sendall(b"ok")

            data = s.recv(1024)
            print(data)
            self.signature = data
            self.print()
            return self.update_in_ca_tree()

    def request_cert_from_server(self, ip, port):
        HOST = ip
        PORT = port

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, int(PORT)))
            s.sendall(b"request_server_cert")
            data = s.recv(20000)
            cert = pickle.loads(data)

            return cert

    def update_in_ca_tree(self):
        # the ip and the port of the ca_tree server
        HOST = GLOBALS.CA_SERVER_IP
        PORT = GLOBALS.CA_SERVER_PORT

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, int(PORT)))
            s.sendall(b"update data")
            data = s.recv(1024)
            # CA1.signer_name, CA1.signature, CA1.msg= pickle.loads(data)
            print(data)
            data = data.decode('utf-8')
            if data != "Please send me your cert":
                print("error")
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            cert = CERT.cert(self.name, self.HOST, self.PORT, self.signer_IP, self.signer_PORT, self.msg,
                             self.signer_name, self.signature,
                             pem, self.start_date, self.end_date, self.CA_FLAG)
            cert.print()
            cert_to_send = pickle.dumps(cert)
            s.sendall(cert_to_send)
            return cert

    def run_as_ca(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print("check")
            print(self.HOST, self.PORT)
            print(type(self.HOST))
            print(type(self.PORT))
            s.bind((self.HOST, self.PORT))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    data = data.decode('utf-8')
                    print(data)

                    if data == "request_server_cert":
                        cert = CERT.cert(self.name, self.HOST, self.PORT, self.signer_IP, self.signer_PORT, self.msg,
                                         self.signer_name,
                                         self.signature, str(self.public_key), self.start_date, self.end_date,
                                         self.CA_FLAG)
                        cert.print()
                        cert_to_send = pickle.dumps(cert)
                        conn.sendall(cert_to_send)
                    if data == "request_public_key":
                        print(data)
                        print(self.name)
                        print(self.public_key)
                        pem = self.public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        conn.sendall(pem)
                        # do something
                    # if data=="get all ca's":
                    #     conn.sendall(
                    #         (name_of_ca + " " + msg + " "

                    if data == "request_cert":
                        self.print()

                        name_of_ca, signar_IP, signar_PORT, signature, msg, start_date, end_date = self.sign_to_another_ca()
                        signar_PORT = int(signar_PORT)
                        print(signar_PORT)
                        print(type(signar_PORT))
                        print(name_of_ca, signar_IP, signar_PORT, signature, msg, start_date, end_date)

                        if self.name == "FAKE":
                            signature = "FAKE".encode()
                        conn.sendall(
                            (name_of_ca + " " + signar_IP + " " + str(signar_PORT) + " " + msg + " " + str(start_date)
                             + " " + str(end_date)).encode('utf-8'))
                        data = conn.recv(1024).decode('utf-8')
                        print(data)
                        if data == "ok":
                            conn.sendall(signature)
                        else:
                            print("eroor")
                        # conn.sendall((name_of_ca + " " + msg).encode('utf-8'),signature)
                    # do something
                else:
                    conn.sendall(data.encode('utf-8'))

    def run_as_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.HOST, self.PORT))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    data = data.decode('utf-8')
                    print(data)

                    if data == "request_server_cert":
                        cert = CERT.cert(self.name, self.HOST, self.PORT, self.signer_IP, self.signer_PORT,
                                         self.msg, self.signer_name,
                                         self.signature, str(self.public_key), self.start_date, self.end_date,
                                         self.CA_FLAG)
                        cert.print()
                        cert_to_send = pickle.dumps(cert)
                        conn.sendall(cert_to_send)

                else:
                    conn.sendall(data.encode('utf-8'))
