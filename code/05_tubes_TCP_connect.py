#!/usr/bin/env python
###############################################################
#
# Script: 05_tubes_tcp_connect.py
#
# Date: 02/16/2018
#
# Author: Travis Phillips
#
# Website: https://github.com/jaxhax-travis/presentation-pwntools
#
# Purpose: A demo script showing how to use pwntools tubes.sock
#          API to start a network connection and use it. This
#          should be used with 06_tubes_tcp_listen.py.
#
###############################################################
from pwn import *

#############################################
# Use remote to attempt to connect to ourself
# on port 31337.
#############################################
conn = remote('127.0.0.1', 31337)

#############################################
# Get the hello Line from the listener.
#############################################
data = conn.recvline()
log.info("Got data from server: {}".format(data))

#############################################
# Send something to the server.
#############################################
conn.sendline("Greetings Kind Server!")

#############################################
# Close it like a socket. just call .close()
# on it. 
#############################################
conn.close()
log.success("Script Finished!")
