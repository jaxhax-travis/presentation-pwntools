#!/usr/bin/env python
###############################################################
#
# Script: 03_ui_prompts.py
#
# Date: 02/16/2018
#
# Author: Travis Phillips
#
# Website: https://github.com/jaxhax-travis/presentation-pwntools
#
# Purpose: A demo script showing how to use pwntools ui prompts
#
###############################################################
from pwn import *

#############################################
# ui.yesno() Demo. Returns True on yes or
# False on no.
#############################################
result = ui.yesno("Do you like Yes/No questions?")
if result:
	log.success("You said yes!")
else:
	log.failure("You said no...")

#############################################
# ui.pause can be passed a number to make it
# wait till that time is up. This is a great
# way to sleep with UI output.
#############################################
log.info("Now we wait 3 seconds before Our next question")
ui.pause(3)

#############################################
# ui.options() Demo.
#############################################
foodOpts = ["Apples", "Oatmeal", "Eggs", "Pancakes"]
res = ui.options("What would you like for breakfast?", foodOpts)
log.info("the 'res' holds '{}'; the offset in foodOpts for '{}'".format(res, foodOpts[res]))

#############################################
# Without a number passed to pause it waits
# till the user hits any key.
#############################################
ui.pause()

log.success("Script Finished!")
