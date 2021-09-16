#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 13 12:45:02 2021

@author: christer
"""
# P2 acts as a server due to the while loop, listening to a dedicated port.
# In this lab, P2 will both initiate sending messages and respond to messages 
# so you need to implement that. For how to initiate a communication, see P1.py.
# Good luck!  

import socket

myIP = "127.0.0.1"
myPort = 3010
bufferSize = 1024

msgFromServer = "Hi P1, Applied Computer Science P2 here, I hope all is secured on your side."
bytesToSend = str.encode(msgFromServer)

# Create a datagram socket and bind to an IP address and port
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPServerSocket.bind((myIP, myPort))
 
print("P2 is up running and ready to go!")

# Wait for incomming calls, any one out there? Hopefully P1.

while(True):
    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    message = bytesAddressPair[0]
    address = bytesAddressPair[1]

    msg = "Message from P1: \n{}".format(message)
    sendersIP  = "P1's Address is:{}".format(address)
    
    print(msg)
    print(sendersIP)

    #Send response to P1
    UDPServerSocket.sendto(bytesToSend, address)