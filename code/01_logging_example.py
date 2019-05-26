#!/usr/bin/env python
###############################################################
#
# Script: 01_logging_example.py
#
# Date: 02/16/2018
#
# Author: Travis Phillips
#
# Website: https://github.com/jaxhax-travis/presentation-pwntools
#
# Purpose: A quick and simple demo of some of pwntools log
#          Functions
#
###############################################################
from pwn import *

#############################################
# Demo some simple output lines
#############################################
log.info("This is an info line!")
log.warn("This is an warn line!")
log.debug("This is an debug line!")
log.success("This is an success line!")
log.failure("This is a failure line!")
log.critical("This is a critical line...")

#############################################
# Using log.error() will throw an exception.
# if you do not catch it, this will crash the
# script with a callback trace.
#############################################
try:
	log.error("This is a fatal error... Better catch it!")
except PwnlibException as e:
	log.success("Nice save!")
	
#############################################
# Demoing indented() which doesn't have any
# bulleting
#############################################
log.indented("This is an indented line! I have no bullet in front")


#############################################
# Demo of info_once() and warn_once(). These
# two ensure a message will only be printed
# once.
#############################################
log.info_once("log.info_once() can make sure you don't see the same message more than once...")
log.info_once("log.info_once() can make sure you don't see the same message more than once...")
log.warn_once("log.warn_once() does the same thing as well!")
log.warn_once("log.warn_once() does the same thing as well!")
log.info_once("log.info_once() can make sure you don't see the same message more than once...")
log.warn_once("log.warn_once() does the same thing as well!")

#############################################
# Changing context.log_level can impact what
# a user sees from log.
#############################################
log.info("You can see me for now!")
context.log_level = 'error'
log.info("But how about now? Did chaning context.log_level impact reading this?")
context.log_level = 'info'
log.info("Can you see this one with the context.log_level change again?")
