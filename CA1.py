import server
import GLOBALS

# get the list of ca- THEIR IP AND PORT


# YOUR IP AND PORT


if __name__ == '__main__':
    # connect exiting ca- in order to be by yourself
    my_self_host = GLOBALS.SON_IP
    port = GLOBALS.SON_PORT
    CA1 = server.CA("CA1", my_self_host, port)

    # GET LIST OF CA1
    # CA_TREE.CA_TREE.print_CA_list(tree)

    # HOST=input("ENTER THE IP OF THE DESIRED ")
    # PORT=input("ENTER THE PORT OF THE DESIRED ")

    HOST = GLOBALS.ROOT_IP

    PORT = GLOBALS.ROOT_PORT

    CA1.request_signature_from_ca(HOST, PORT)
    while True:
        CA1.run_as_ca()

    # became CA

    # LISTEN TO ANOTHER

# להצפים מידע שעובר?
