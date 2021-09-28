#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Sep 26 17:52:43 2021

@author: christer
"""

import sys
import matplotlib.pyplot as plt
import pyotp
import qrcode

multiFactorAuthEnabled = False

# See this as a local database hosting user and password
correctUsername = "jakoli123"
correctPassword = "jakoli123"
#########################################################

# Functionn for verifying username and password
def login():
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    if username == correctUsername and password == correctPassword:
        return True
    else:
        return False


# Enables multifactor authentication
def registerMFA():
    global t, multiFactorAuthEnabled

    t = pyotp.TOTP("AnInitialSecrecy")
    auth_str = t.provisioning_uri(
        name="MG@AppliedComputerSecurity", issuer_name="AppliedComputerSecurity"
    )
    img = qrcode.make(auth_str)
    plt.imshow(img)
    plt.show()
    input("Scan the QR-code with Google Authenticator and press Enter")
    multiFactorAuthEnabled = True


# The menu takes your choice and enables you to login with or without MFA
def menu():
    alt = input(
        """ 
        A: Register for Multifactor Authentication 
        B: Login
        Q: Quit
        Enter your choice: """
    )

    if alt == "A" or alt == "a":
        registerMFA()
    elif alt == "B" or alt == "b":
        if login() == False:
            print("\nNo such user or the password is incorrect!")
        elif multiFactorAuthEnabled == True:
            multiFactorAuth = input("Enter code: ")
            if multiFactorAuth == t.now():
                print("\nThe login was successfull!")
            else:
                print("\nWrong authentication code entered!")
        else:
            print("\nThe login was successfull!")
    elif alt == "Q" or alt == "q":
        sys.exit()


print("!!!!!!!!!!!!! Welcome to a MF-Authentication Demo !!!!!!!!!!!!!\n")
while True:
    menu()
