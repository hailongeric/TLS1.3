#!/usr/bin/python3
# -*- coding: UTF-8 -*-
from tls13.client import client_main
from tls13.server import server_main
from tls13.utilization.socket import host_port


def main():
    while(True):
        select = int(input("Please choose:\n1.clinet\n2.server\n"
                           "3.modify host and port\n"))
        assert type(select) is int
        if select == 1:
            client_main()
        elif select == 2:
            server_main()
        elif select == 3:
            host_port()
        else:
            print("Unknown choose: {}".format(select))


if __name__ == "__main__":
    main()
