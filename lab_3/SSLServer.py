#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 21 19:11:30 2021

@author: christer
"""

import socket
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
import ssl

listen_addr = '127.0.0.1'
listen_port = 8101
server_cert = 'put the name of the servers certificate file here'
client_certs = 'put the name of the client certificate file here'
server_key = 'put the name of servers private key here'

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.verify_mode = ssl.CERT_REQUIRED
context.load_cert_chain(certfile=server_cert, keyfile=server_key)
context.load_verify_locations(cafile=client_certs)

bindsocket = socket.socket()
bindsocket.bind((listen_addr, listen_port))
bindsocket.listen(5)

#while True:
print("Waiting for client")
newsocket, fromaddr = bindsocket.accept()
print("Client connected: {}:{}".format(fromaddr[0], fromaddr[1]))
conn = context.wrap_socket(newsocket, server_side=True)
print("SSL established. Peer: {}\n".format(conn.getpeercert()))

#WAit for a message from the client
data = conn.recv(4096)
print (data)
print("\nClosing connection")
conn.shutdown(socket.SHUT_RDWR)
conn.close()