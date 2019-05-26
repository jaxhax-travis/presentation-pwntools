#!/usr/bin/env python
###############################################################
#
# Script: 07_tubes_ssh.py
#
# Date: 02/16/2018
#
# Author: Travis Phillips
#
# Website: https://github.com/jaxhax-travis/presentation-pwntools
#
# Purpose: A demo script showing how to use pwntools tubes.ssh
#          API to connect to overthewire bandit0 and cat the
#          readme.
#
###############################################################
from pwn import *

conn = ssh("bandit0", "bandit.labs.overthewire.org", port=2220, password="bandit0")

log.info("Current Directory: {}".format(conn.pwd()))
log.info("Directory Listing: {}".format(conn.ls()))
log.success("Readme Contains: {}".format(conn.cat('readme')))
conn.close()
log.success("Script Finished!")
