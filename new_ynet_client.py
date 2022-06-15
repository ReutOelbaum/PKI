import new_entity_interface
import GLOBALS
import time

if __name__ == '__main__':

    # connect exiting ca- in order to be  ca by yourself/ get cert
    my_host = "127.2.2.0"
    my_port = 12344
    my_name = "client3"
    new_entity_interface.run(my_host, my_port, my_name)