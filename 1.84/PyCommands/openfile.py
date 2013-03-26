#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}

openfile example

"""

__VERSION__ = '1.0'

DESC="""Open a File"""

import immlib

def usage(imm):
    imm.log("!openfile file")
    imm.log("ex: !openfile c:\\boot.ini", focus=1)

def main(args):
    imm=immlib.Debugger()
    if not args:
        usage(imm)
        return "Wrong Arguments (Check Log Windows for the usage information)"
    ret = imm.openTextFile( args[0] )
    if ret == 0:
        return "File %s open" % args[0] 
    else:
        return "Cannot open %s" % args[0]
    
