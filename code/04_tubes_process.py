#!/usr/bin/env python
###############################################################
#
# Script: 04_tubes_process.py
#
# Date: 02/16/2018
#
# Author: Travis Phillips
#
# Website: https://github.com/jaxhax-travis/presentation-pwntools
#
# Purpose: A demo script showing how to use pwntools tubes.process
#          API to start a process and read from it.
#
###############################################################
from pwn import *

#############################################
# Use tubes.process() to create a tube to the
# /bin/bash process.
#############################################
log.info("Starting Bash Shell...")
conn = process("/bin/bash")

#############################################
# it acts like a socket or anything else.
# This makes it easy to work with processes.
#
# In this case, we will send it a simple ls
# command on /dev/
#############################################
log.info("Sending ls -l /dev/ commmand in 3 seconds")
ui.pause(3)
conn.sendline("ls -l /dev/")

#############################################
# And now we will read all lines available to
# us from the ls command.
#############################################
while conn.can_recv(1):
	log.indented(conn.recvline())

#############################################
# Tubes also supports interactive mode on any
# type of tube (process, sock, serial, ssh, etc).
#
# This means if it pops a shell you can use it
# directly, or if something is harder to script
# then just user interaction, just flip it over
# to the user. 
#############################################
log.info("Going interactive, press Ctrl+D when done...")
conn.interactive()

#############################################
# Killing the process is as easy as closing
# a file or socket. just call .close() on it. 
#############################################
conn.close()
log.success("Script Finished!")
