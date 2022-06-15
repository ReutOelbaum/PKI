import server
import cryptography.exceptions
import socket
import pickle
import base64
import time
from datetime import date
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
import GLOBALS


def get_all_valid_ca_and_servers():
    HOST = GLOBALS.CA_SERVER_IP
    PORT = GLOBALS.CA_SERVER_PORT
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, int(PORT)))
        s.sendall(b"get all ca's")
        data = s.recv(20000)
        CA_LIST = pickle.loads(data)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, int(PORT)))
        s.sendall(b"get all server's")
        data = s.recv(20000)
        servers_list = pickle.loads(data)
        return CA_LIST, servers_list


def get_revocation_list():
    HOST = GLOBALS.CA_SERVER_IP
    PORT = GLOBALS.CA_SERVER_PORT
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, int(PORT)))
        s.sendall(b"get revocation list")
        data = s.recv(20000)
        data = data.decode('utf-8')

        print(data)
        if data == "The list is empty":
            print("error")
            return "The list is empty"
        # s.sendall(b"ok")
        # data = s.recv(20000)
        revocation_list = pickle.loads(data)
        print(revocation_list)
        return revocation_list


def request_cert_from_server(ip, port):
    HOST = ip
    PORT = port

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, int(PORT)))
        s.sendall(b"request_server_cert")
        data = s.recv(20000)
        cert = pickle.loads(data)

        return cert


def request_public_key_from_ca(signer_ip, signer_port):
    HOST = signer_ip
    PORT = signer_port

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(HOST, PORT)
        s.connect((HOST, int(PORT)))
        s.sendall(b"request_public_key")
        pubkey = s.recv(1024)
        # CA1.signer_name, CA1.signature, CA1.msg= pickle.loads(data)

        pubkey = pubkey.decode()

        b64data = '\n'.join(pubkey.splitlines()[1:-1])
        derdata = base64.b64decode(b64data)
        key = load_der_public_key(derdata, default_backend())

        return key


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


def get_and_validate_chain(cert):
    start = time.time()


    while cert.signer_name is not None:
        if get_revocation_list() != "The list is empty":
            if cert in get_revocation_list():
                print("The cert in revocation list")
                return False
        signar_public_key = request_public_key_from_ca(cert.signer_IP, cert.signer_PORT)
        try:
            if verify_using_public_key(cert.signature, cert.msg, signar_public_key) is None:
                # check if current date is valid
                print(date.today())
                print(datetime.strptime(cert.end_date, '%Y-%m-%d').date())
                if datetime.strptime(cert.end_date, '%Y-%m-%d').date() < date.today():
                    print("Expired")
                    return False

                name = cert.signer_name
                cert = request_cert_from_server(cert.signer_IP, cert.signer_PORT)
            else:
                print("error")
                return False
        except cryptography.exceptions.InvalidSignature as e:
            print(" Error! .Invalid Signature")
            return False
        except Exception as e:
            print(e)
            return False

    end = time.time()
    latency = end - start
    print("time to validate cert")
    print(latency)
    return True


def run(my_host, my_port, my_name):
    res = input("Do you want to serve as [1]ca or [2]end_server [3]end_client")
    while res != str(2) and res != str(1) and res != str(3):
        print("Invalid input")
        res = input("Do you want to serve as [1]ca or [2]end_server [3]end_client")
    entity = ""
    if res == str(1):
        CA = server.CA(my_name, my_host, my_port)
        CA.CA_FLAG = True
        entity = "server"
        print(entity)

    if res == str(2):
        CA = server.CA(my_name, my_host, my_port)
        CA.CA_FLAG = False
        entity = "server"
    if res == str(3):
        entity = "client"

    valid_ca, valid_servers = get_all_valid_ca_and_servers()
    print("The valid ca's")
    print(valid_ca)
    print("The valid server's")
    print(valid_servers)

    if entity == "client":
        HOST = input("The SERVER IP")
        PORT = input("The SERVER PORT")
        cert = request_cert_from_server(HOST, PORT)
        print(cert)
        validity_check = get_and_validate_chain(cert)
        if not validity_check:
            print("Error. Not valid cert for the desired Server")
            exit()
        else:
            print("The Server has valid cert")

    if entity == "server":

        HOST = input("The SERVER IP")
        PORT = int(input("The SERVER PORT"))

        cert = CA.request_signature_from_ca(HOST, PORT)
        print(cert)

        if CA.CA_FLAG:

            while True:
                print("run as CA")
                CA.run_as_ca()
        else:

            while True:
                print("run as server")
                CA.run_as_server()
