#!/usr/bin/env python
###############################################################
#
# Script: 02_progress_example.py
#
# Date: 02/16/2018
#
# Author: Travis Phillips
#
# Website: https://github.com/jaxhax-travis/presentation-pwntools
#
# Purpose: A demo script showing how to use pwntools
#          log.progress() functionality for a spinner line
#
###############################################################
from pwn import *

#############################################
# Create a simple spinner to show sleeping
# for 5 seconds while counting the seconds.
#############################################
log.info("And now for a single line spinner progress line!")
p = log.progress("Sleeping for 5 seconds")
for i in xrange(1,6):
	p.status("Slept {} seconds...".format(i))
	sleep(1)
p.success("Done sleeping!")

#############################################
# Show a counting loop to demo counting. This
# allows people to see the refresh rate.
#############################################
log.info("And to demo refresh rate....")
p = log.progress("Counting to a 31337")
for i in xrange(1,31338):
	p.status("{}/31337...".format(i))
p.success("Done counting!")

log.success("Script Finished")
