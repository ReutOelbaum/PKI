import rsa
import string, random, socket, pickle
import CERT
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key


import server
import GLOBALS

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


if __name__ == '__main__':
    # SERVER
    MY_HOST = GLOBALS.FAKE_IP
    MY_PORT = GLOBALS.FAKE_PORT



    CA_FAKE = server.CA("CA_ROOT", MY_HOST, MY_PORT)


    #CA_FAKE.request_signature_from_ca(HOST, PORT)
    CA_FAKE.signer_name=None
    CA_FAKE.msg = "BLA"
    CA_FAKE.signature=sign_using_private_key(CA_FAKE.msg, CA_FAKE.private_key)

    while True:
        CA_FAKE.run_as_ca()

