#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 21 19:13:14 2021

@author: christer
"""

import socket
import ssl

host_addr = '127.0.0.1' # Local host
host_port = 8101
server_sni_hostname = 'place the FQDN here, e.g. AppliedComputerSecurity.ltu'
server_cert = 'put the name of the servers certificate file here'
client_cert = 'put the name of the client certificate file here'
client_key = 'put the name of client private key here'

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_cert)
context.load_cert_chain(certfile=client_cert, keyfile=client_key)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn = context.wrap_socket(s, server_side=False, server_hostname=server_sni_hostname)
conn.connect((host_addr, host_port))
print("SSL established. Peer: {}".format(conn.getpeercert()))
conn.send(b"Students in Applied Computer Security trying out certificates")
input('Now, go and check if the server got our message, did it work (Y/N)?')
conn.close()
