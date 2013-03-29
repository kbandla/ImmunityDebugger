#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}
"""
__VERSION__ = '1.0'

import immlib, string
import traceback
import sys

DESC = "Non interactive python shell [immlib already imported]"

def usage(imm):
    imm.log("!pyexec code")
    imm.log("%s" % DESC)

def main(args):
    imm = immlib.Debugger()
    if args:
        commands = string.joinfields(args, "")
        try:
            exec commands
        except:            
            error = traceback.format_exception_only(sys.exc_type, sys.exc_value)
            imm.log("Error on: %s" % commands, focus = 1)
            for line in error: # Its just one line anyways, for format_exception_only
                line = line.strip()
                imm.log(line) 
            return line
    else:
        return "No python command given"
