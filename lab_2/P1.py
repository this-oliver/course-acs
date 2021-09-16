#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 13 12:47:58 2021

@author: christer
"""

import socket

msgFromP1 = "Hello P2, are you ready to start?"
bytesToSend = str.encode(msgFromP1)
serverAddressPort = ("127.0.0.1", 3010)
bufferSize = 1024

# Create a UDP socket
UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)


# Contact P2
msg = "Message to be sent to P2: \n{}".format(msgFromP1)
print(msg)
UDPClientSocket.sendto(bytesToSend, serverAddressPort)

# P1's response
msgFromServer = UDPClientSocket.recvfrom(bufferSize)
msg = "Reply from P2: \n {}".format(msgFromServer[0])
print(msg)