#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004 - 2007


U{Immunity Inc.<http://www.immunityinc.com>}

"""


__VERSION__ = '1.0'

import immlib

DESC = "Return the usage information for a python command"

def usage(imm):
    imm.log("!usage  Returns the usage information for a pytho command")

def main(args):
    imm = immlib.Debugger()
    if args:
        try:
            mod = __import__(args[0])
        except ImportError:
            return "Error: %s is not a python command" % args[0]
        try:
            return mod.usage(imm)
        except AttributeError:
            return "Sorry, no usage available for this command"
    else:
        return "No arguments given"
