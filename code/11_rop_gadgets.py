#!/usr/bin/env python
###############################################################
#
# Script: 11_rop_gadgets.py
#
# Date: 02/16/2018
#
# Author: Travis Phillips
#
# Website: https://github.com/jaxhax-travis/presentation-pwntools
#
# Purpose: A demo script showing how to use pwntools ELF
#          module to generate a ROP object and use it to ease ROP
#          chaining stack frames. This is intended to be used with
#          the supplied pwntools_demo_pwn_me ELF that is generated
#          from pwntools_demo_pwn_me.c
#
###############################################################
from pwn import *

#############################################
# Open the ELF binary using the pwntools ELF()
# class. Checksec runs by default but can
# be disable if desired.
#############################################
log.info("Opening ./pwntools_demo_pwn_me")
e = ELF('./pwntools_demo_pwn_me', checksec=False)
#e = ELF('./pwntools_demo_pwn_me')

#############################################
# Create a ROP object from the ELF object. 
#############################################
log.info("Creating ROP object")
r = ROP(e)

#############################################
# Print a list of ROP gadgets found.
#############################################
log.info("Dumping ROP Gadgets")
for k,v in r.gadgets.iteritems():
	log.info("0x{:08x}:".format(k))
	for i in v.insns:
		log.indented("\t{}".format(i))
print("")

#############################################
# Building a kinda useless ROP chain, but it
# shows how you can use functions already 
# present or imported in a binary. Look at
# the dump, it automagically handles pop/ret
# placement
#############################################
log.info("Building a simple bzero(bss,4)/neverCalledWinnerFunction/exit rop chain.")
r.bzero(e.bss(), 4)
r.neverCalledWinnerFunction()
r.exit()
print(r.dump())
print("")

#############################################
# Use r.chain() to generate a binary string
# of the ROP chain built.
#############################################
log.info("ROP: {}".format(r.chain()))

print("")
log.success("Script Finished!")
