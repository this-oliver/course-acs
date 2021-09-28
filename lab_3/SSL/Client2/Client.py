#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 21 19:13:14 2021

@author: christer
"""

import socket
import ssl

server_addr = "127.0.0.1"  # Local host
server_port = 8101
server_sni_hostname = "ltu.se"

client_key = "./key.pem"
client_cert = "./cert.pem"
server_cert = "./../Server/cert.crt"

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_cert)
context.load_cert_chain(certfile=client_cert, keyfile=client_key)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn = context.wrap_socket(s, server_side=False, server_hostname=server_sni_hostname)
conn.connect((server_addr, server_port))
print("SSL established.\n")
print("Server certificate: {}\n".format(conn.getpeercert()))
conn.send(b"Students in Applied Computer Security trying out certificates")
input("Now, go and check if the server got our message, did it work (Y/N)?")
conn.close()
