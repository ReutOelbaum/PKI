import new_entity_interface
import GLOBALS

if __name__ == '__main__':

    my_host = GLOBALS.GRANDSON_IP
    my_port = GLOBALS.GRANDSON_PORT
    my_name = "GENERIC_NAME"
    new_entity_interface.run(my_host, my_port, my_name)
