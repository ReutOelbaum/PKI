# echo-server.py
import server
import socket
import GLOBALS

if __name__ == '__main__':
    # SERVER
    HOST = GLOBALS.ROOT_IP
    PORT = GLOBALS.ROOT_PORT

    CA_ROOT = server.CA("CA_ROOT", HOST, PORT)
    CA_ROOT.signer_name= None
    CA_ROOT.update_in_ca_tree()
    while True:
        CA_ROOT.run_as_ca()

