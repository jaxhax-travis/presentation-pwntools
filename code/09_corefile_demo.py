#!/usr/bin/env python
###############################################################
#
# Script: 09_corefile_demo.py
#
# Date: 02/16/2018
#
# Author: Travis Phillips
#
# Website: https://github.com/jaxhax-travis/presentation-pwntools
#
# Purpose: A demo script how to use the corefile module. It will attempt to
#          set ulimit, run the pwntools_demo_pwn_me_binary and crash it, open
#          the core dump, and display various bits of information on the crash.
#          This is intended to be used with the supplied pwntools_demo_pwn_me
#          ELF that is generated from pwntools_demo_pwn_me.c. Feel free to
#          change the buffer size in vulnFunc() and watch it still work.
#
###############################################################
from pwn import *
import os
import sys

################################
# Constants
################################
BINARY="./pwntools_demo_pwn_me"

########################################################################
# Support Functions
########################################################################
def RunProcessSilent(args, inShell=False):
	context.log_level = 'error'
	p = process(args, shell=inShell)
	p.wait_for_close()
	p.close()
	context.log_level = 'info'

def CleanCoreDump():
	if os.path.isfile('./core'):
		os.remove('./core')

def OpenCoreDump():
	context.log_level = 'error'
	core = Coredump('./core')
	context.log_level = 'info'
	return core

def extendedTesting(offset):
	log.info("Possible EIP overwrite Offset {}. Testing EIP Overwrite 0x41414141".format(offset))
	RunProcessSilent([BINARY, cyclic(offset) + "AAAA"])
	core = OpenCoreDump()
	if core.eip != 0x41414141:
		log.failure("EIP Overwrite 0x41414141 Failed: Actual => 0x{:08x}".format(core.eip))
		return False
	
	log.info("Possible EIP overwrite Offset {}. Testing EIP Overwrite 0x42424242".format(offset))
	RunProcessSilent([BINARY, cyclic(offset) + "BBBB"])
	core = OpenCoreDump()
	if core.eip != 0x42424242:
		log.failure("EIP Overwrite 0x42424242 Failed: Actual => 0x{:08x}".format(core.eip))
		return False
	
	log.info("Possible EIP overwrite Offset {}. Testing EIP Overwrite 0xdeadbeef".format(offset))
	RunProcessSilent([BINARY, cyclic(offset) + p32(0xdeadbeef)])
	core = OpenCoreDump()
	if core.eip != 0xdeadbeef:
		log.failure("EIP Overwrite 0xdeadbeef Failed: Actual => 0x{:08x}".format(core.eip))
		return False

	return True

########################################################################
# Main Code
########################################################################

#############################################
# Check for binary.
#############################################
if os.path.isfile(BINARY) == False:
	log.failure("You appear to be missing '{}'. Aborting!".format(BINARY))
	sys.exit(1)

#############################################
# Open it with ELF() and make sure it's
# executable.
#############################################
log.info("Opening {}".format(BINARY))
e = ELF(BINARY, checksec=False)
if e.executable == False:
	log.failure("{} doesn't seem to be executable. Aborting!".format(BINARY))
	sys.exit(2)

#############################################
# Make sure our shell has ulimit ran on it
#############################################
log.info("Setting \"ulimit -c unlimited\" on shell...")
RunProcessSilent(["ulimit", "-c", "unlimited"], True)

#############################################
# Check if a core dump file already exist.
# delete it if it does.
#############################################
CleanCoreDump()

#############################################
# Try to generate a core file.
#############################################
log.info("Attempting to crash {} for a coredump file.".format(BINARY))
RunProcessSilent([BINARY, "A"*5000])

#############################################
# Check for a core file
#############################################
if os.path.isfile('./core'):

	#############################################
	# If we have a core dump file, open it and
	# check if the EIP is in the pattern
	#############################################
	log.info("Found Core dump file, opening...")
	core = OpenCoreDump()
	
	
	print("\n\033[33;1m\t---===[ General Information ]===---\n\033[0m")
	log.info("Signal: {}".format(core.signal))
	log.info("Fault Address: 0x{:08x}".format(core.fault_addr))
	log.info("PID: {}".format(core.pid))
	
	#############################################
	# Show a lazy approach to get all registers.
	#############################################
	print("\n\t\033[33;1m---===[ Registers Dump Via Loop ]===---\033[0m")
	for reg,val in core.registers.iteritems():
		log.indented("{} => 0x{:08x}".format(reg, val))
	
	print("\n\t\033[33;1m---===[ Direct Access Registers ]===---\033[0m")
	log.info("EIP: 0x{:08x}".format(core.eip))
	log.info("ESP: 0x{:08x}".format(core.esp))
	log.info("EBP: 0x{:08x}".format(core.ebp))
	log.info("EAX: 0x{:08x}".format(core.eax))
	log.info("EBX: 0x{:08x}".format(core.ebx))
	
	print("\n\t\033[33;1m---===[ VMMAP ]===---\033[0m")
	for mapping in core.mappings:
		print(mapping)
	
	print("\n\t\033[33;1m---===[ Stack ]===---\033[0m")
	condensed_stack = core.stack.data.replace("\x00\x00\x00\x00", "")
	log.info("Stack Size: {}".format(len(core.stack.data)))
	log.info("Condensed Stack Size: {}".format(len(condensed_stack)))
	if ui.yesno("Do you want to dump the stack (A ton of data!)"):
		if ui.yesno("Would you like a condensed stack? (NULL Dwords cut out...)"):
			print("\n{}\n".format(condensed_stack))
		else:
			print("\n{}\n".format(core.stack.data))
	
	print("")
	log.info("Deleting Core Dump File...")
	CleanCoreDump()

log.success("Script Finished!\n\n")
