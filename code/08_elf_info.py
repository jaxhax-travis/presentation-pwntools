#!/usr/bin/env python
###############################################################
#
# Script: 08_elf_info.py
#
# Date: 02/16/2018
#
# Author: Travis Phillips
#
# Website: https://github.com/jaxhax-travis/presentation-pwntools
#
# Purpose: A demo script showing how to use pwntools ELF
#          module to gather some basic information about
#          an ELF binary. This is intended to be used with
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
# Once it is open, Let's show the user the
# architecure, bitness, endian order, etc.
#############################################
print("\n\t\033[33;1m---===[ General Information ]===---\033[0m")
log.info("Type: {}".format(e.elftype))
log.info("Architecture: {}".format(e.arch))
log.info("Bitness: {} bit".format(e.bits))
log.info("Endian Order: {}".format(e.endian))
log.info("Entry Point: 0x{:08x}".format(e.entry))
log.info("Number of RWX Segments: {}".format(len(e.rwx_segments)))
log.info("Statically Linked: {}".format(e.statically_linked))
log.info("UPX Packed: {}".format(e.packed))

#############################################
# And security information...
#############################################
print("\n\t\033[33;1m---===[ Security Information ]===---\033[0m")
log.info("ASLR: {}".format(e.aslr))
log.info("ASAN: {}".format(e.asan))
log.info("DEP: {}".format(not e.execstack))
log.info("Canary: {}".format(e.canary))
log.info("Fortify: {}".format(e.fortify))
log.info("MSAN: {}".format(e.msan))
log.info("PIE: {}".format(e.pie))
log.info("RELRO: {}".format(e.relro))
log.info("UBSAN: {}".format(e.ubsan))
log.info("RPATH: {}".format(e.rpath))

#############################################
# And Sections...
#############################################
print("\n\t\033[33;1m---===[ Sections ]===---\033[0m")
log.info("Number of Sections: {}".format(e.num_sections()))
for i in e.sections:
	if i.name != "":
		log.indented("0x{:08x} - 0x{:04x} Bytes => {}".format(i.header['sh_addr'], i.header['sh_size'], i.name))

#############################################
# And Segments...
#############################################
print("\n\t\033[33;1m---===[ Segments ]===---\033[0m")
log.info("Number of Segments: {}".format(e.num_segments()))
for i in e.segments:
	log.indented("0x{:08x} => {}".format(i.header['p_paddr'], i.header['p_type']))

#############################################
# And and plt Entries...
#############################################
print("\n\t\033[33;1m---===[ PLT Entries ]===---\033[0m")
log.info("Number of PLT Entries: {}".format(len(e.plt)))
for k,v in e.plt.iteritems():
	log.indented("0x{:08x} => {}".format(v, k))

#############################################
# And and Functions...
#############################################
print("\n\t\033[33;1m---===[ Functions ]===---\033[0m")
log.info("Number of Functions: {}".format(len(e.functions)))
for k,v in e.functions.iteritems():
	log.indented("0x{:08x} - 0x{:02x} bytes => {}".format(v.address, v.size, k))

#############################################
# And and Functions...
#############################################
print("\n\t\033[33;1m---===[ Demo Direct Named Access ]===---\033[0m")
log.info("BSS: 0x{:08x}".format(e.bss()))
log.info("BSS+0x20: 0x{:08x}".format(e.bss(0x20)))
log.info("Strcpy@plt: 0x{:08x}".format(e.plt['strcpy']))
log.info("vulnFunc: 0x{:08x}".format(e.functions['vulnFunc'].address))
log.info("neverCalledWinnerFunction: 0x{:08x}".format(e.functions['neverCalledWinnerFunction'].address))

print("")
log.success("Script Finished!")
