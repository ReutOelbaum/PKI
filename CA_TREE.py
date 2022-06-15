import cryptography.exceptions
from treelib import Tree
import socket
import pickle
import base64
from datetime import date
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
import GLOBALS


def load_public_key(pem):
    pubkey = pem.decode()
    b64data = '\n'.join(pubkey.splitlines()[1:-1])
    derdata = base64.b64decode(b64data)
    key = load_der_public_key(derdata, default_backend())
    return key


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


def example(desp):
    sep = "-" * 20 + '\n'
    print(sep + desp)


# add private public. WHO HAS ACCESS TO WHAT

class CA_TREE:
    def __init__(self):
        self.HOST = GLOBALS.CA_SERVER_IP
        self.PORT = GLOBALS.CA_SERVER_PORT
        self.tree = Tree()
        self.tree_with_servers = Tree()
        # root node
        self.revocation_list = []
        self.CA_LIST = {}
        self.List_of_ca = []  # (name,port, host)
        self.List_of_servers = []  # (name,port, host)

    def print_tree(self):
        example("Tree of the whole family:")
        self.tree.show(key=lambda x: x.tag, reverse=True, line_type='ascii-em')
        self.tree_with_servers.show(key=lambda x: x.tag, reverse=True, line_type='ascii-em')

    def print_CA_list(self):
        # for item in self.CA_LIST:
        #     print(self.CA_LIST[item].name)
        print(self.List_of_ca)
        print(self.CA_LIST)

    def print_servers_list(self):
        # for item in self.CA_LIST:
        #     print(self.CA_LIST[item].name)
        print(self.List_of_servers)

    def add_new_ca(self, name, parent, IP, PORT, cert):
        example("New CA:")
        new_tree = Tree()
        new_tree2 = Tree()
        if str(name) == "CA_ROOT":
            self.tree.create_node("CA_ROOT", "CA_ROOT")
            self.tree_with_servers.create_node("CA_ROOT", "CA_ROOT")
        else:
            if cert.CA_FLAG:
                print("we are here")
                new_tree.create_node(str(name), str(name))  # root node
                self.tree.paste(parent, new_tree)
                new_tree2.create_node(str(name), str(name))  # root node
                self.tree_with_servers.paste(parent, new_tree2)
            else:
                new_tree.create_node(str(name), str(name))  # root node
                self.tree_with_servers.paste(parent, new_tree)

        print(cert.CA_FLAG)
        if cert.CA_FLAG:
            self.CA_LIST[name] = cert
            self.List_of_ca.append((name, IP, PORT))
            self.print_CA_list()
            print("new CA+" + name)
        else:  # it is server with cert
            self.List_of_servers.append((name, IP, PORT))
            self.print_servers_list()
        self.print_tree()

    def add_cert_to_revocation_list(self, cert):
        self.revocation_list.appennd(cert)

    def is_cert_name_in_revocation_list(self, cert_name):
        for cert in self.revocation_list:
            if cert.name == cert_name:
                return True
        return False

    def get_cert_by_name(self, name):
        return self.CA_LIST[name]

    def get_and_valiate_chain(self, cert):
        while cert.signer_name != None:
            # try:
            # cert.signature=str.encode(cert.signature)
            if cert in self.revocation_list:
                print("The cert in revocation list")
                return False

            # signar_public_key=request_public_key_from_ca(self.CA_LIST[cert.signer_name].IP, self.CA_LIST[cert.signer_name].PORT)
            if cert.signer_name not in self.CA_LIST:
                print(cert.signer_name)
                print("Error!. Not such signer name")
                return False
            signar_public_key = load_public_key(self.CA_LIST[cert.signer_name].public_key)

            try:
                if None == verify_using_public_key(cert.signature, cert.msg, signar_public_key):
                    # check if current date is valid
                    print(date.today())
                    print(datetime.strptime(cert.end_date, '%Y-%m-%d').date())
                    if datetime.strptime(cert.end_date, '%Y-%m-%d').date() < date.today():
                        print("Expired")
                        return False

                    name = cert.signer_name
                    cert = self.get_cert_by_name(name)
                else:
                    print("Error")
                    return False
            except cryptography.exceptions.InvalidSignature as e:
                print(" Eroor! .Invalid Signature")
                print(e)
                return False
            except Exception as e:
                print(e)
                print("error")
                return False

        return True
        # except:
        #     print("error")

    def run(self):
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self.HOST, self.PORT))
                s.listen()
                conn, addr = s.accept()
                with conn:
                    print(f"Connected by {addr}")
                    while True:
                        try:
                            data = conn.recv(1024)
                        except:
                            break
                        if data == b'':
                            break
                        data = data.decode('utf-8')
                        print(data)
                        if data == "get revocation list":
                            print(self.revocation_list)
                            if self.revocation_list == []:
                                conn.sendall(b"The list is empty")
                            else:
                                # s.sendall(b"The list is not empty")
                                revocation_list = pickle.dumps(self.revocation_list)
                                conn.sendall(revocation_list)

                        if data == "add cert to revoke":
                            conn.sendall("Please send me the cert".encode('utf-8'))

                            data = conn.recv(20000)

                            cert = pickle.loads(data)
                            self.add_cert_to_revocation_list(cert)

                        if data == "check if cert is valid":
                            conn.sendall("Please send me the cert".encode('utf-8'))

                            data = conn.recv(20000)

                            cert = pickle.loads(data)

                            if self.get_and_valiate_chain(cert):
                                s.sendall(b"The cert is valid (signature and date)")
                            else:
                                if cert in self.revocation_list:
                                    s.sendall(b"The cert is in rhe revocation list")
                                else:
                                    s.sendall(b"The cert is unValid- date/signature")

                        if data == "get all ca's":
                            print("as")
                            cert_to_send = pickle.dumps(self.List_of_ca)
                            conn.sendall(cert_to_send)

                        if data == "get all server's":
                            cert_to_send = pickle.dumps(self.List_of_servers)
                            conn.sendall(cert_to_send)

                        if data == "get_revocation_list":
                            revocation_list = pickle.dumps(self.revocation_list)
                            conn.sendall(revocation_list)

                        if data == "print data":
                            self.print_tree()
                            self.print_CA_list()
                        if data == "PRINT revokcation  list":
                            print(self.revocation_list)
                        if data == "update data":
                            conn.sendall("Please send me your cert".encode('utf-8'))

                            data = conn.recv(20000)

                            cert = pickle.loads(data)

                            if self.get_and_valiate_chain(cert):
                                # add the ca to the tree
                                if cert.name not in self.CA_LIST:

                                    self.add_new_ca(cert.name, cert.signer_name, cert.IP, cert.PORT, cert)
                                else:
                                    print("check")
                                conn.sendall("Valid cert".encode('utf-8'))

                            else:
                                conn.sendall("Invalid cert".encode('utf-8'))
                                self.revocation_list.append(cert)
                                print(self.revocation_list)

                            self.print_tree()

                        else:
                            conn.sendall(data.encode('utf-8'))


if __name__ == '__main__':
    tree = CA_TREE()
    tree.run()

# איך עושים שזה גלובלי. כרגע מניחה שידוע לכולם
