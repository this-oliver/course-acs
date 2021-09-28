#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 21 19:11:30 2021

@author: christer
"""

import socket
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
import ssl

listen_addr = "127.0.0.1"
listen_port = 8101

# configure server variables below
server_key = "./key.pem"
server_cert = "./cert.crt"
client_cert = "./../Client/cert.crt"
client2_cert = "./../Client2/cert.pem"

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
# make certificates mandatory
context.verify_mode = ssl.CERT_REQUIRED
# setting up the server certificate and private key
context.load_cert_chain(certfile=server_cert, keyfile=server_key)
# setup list of certificates that should be verified (and allowed?)
context.load_verify_locations(cafile=client_cert)
context.load_verify_locations(cafile=client2_cert)

bindsocket = socket.socket()
bindsocket.bind((listen_addr, listen_port))
bindsocket.listen(5)

# while True:
print("Waiting for client")
newsocket, fromaddr = bindsocket.accept()
print("Client connected: {}:{}".format(fromaddr[0], fromaddr[1]))
conn = context.wrap_socket(newsocket, server_side=True)
print("SSL established.\n")
print("Client: {}\n".format(conn.getpeercert()))

# Wait for a message from the client
data = conn.recv(4096)
print(data)
print("\nClosing connection")
conn.shutdown(socket.SHUT_RDWR)
conn.close()
