#!/usr/bin/env python
###############################################################
#
# Script: 06_tubes_tcp_listen.py
#
# Date: 02/16/2018
#
# Author: Travis Phillips
#
# Website: https://github.com/jaxhax-travis/presentation-pwntools
#
# Purpose: A demo script showing how to use pwntools tubes.sock
#          API to start a network listener and use it. This
#          should be used with 05_tubes_tcp_connect.py.
#
###############################################################
from pwn import *

#############################################
# Use tubes.sock listen() to bind a listener
# on TCP port 31337.
#############################################
log.info("Creating Listener on port 31337...")
conn = listen(31337)

#############################################
# Wait for a connection.
#############################################
conn.wait_for_connection()

#############################################
# Send the client a Hello.
#############################################
log.info("Sending the client a hello message...")
conn.sendline("Hello Client!")

#############################################
# recvline() from the client and print it
# out. Timeout in 10 seconds however...
#############################################
log.info("Waiting for data up to 10 seconds...")
data = conn.recvline(timeout=10)
log.info("Got data from client: {}".format(data))

#############################################
# Disconnect from the client.
#############################################
conn.close()
log.success("Script Finished!")
