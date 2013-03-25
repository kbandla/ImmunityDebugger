#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}

TODO:
  Fix the Offset in order to actually point to the address where the ID was found. (This is just a really beta version of this script)
"""


__VERSION__ = '1.0'

import immlib
import getopt
import struct

DESC = """Find a Packer/Cryptor on a Module (Note: It might take some times due to the amount of signature on our db)"""

def usage(imm):
    imm.log("!findpacker [-f] -m filename/module Get the RPC information of a loaded dll or for all loaded DLL's",focus=1)
    imm.log("   -m  filename/module   File or Module to search for")
    imm.log("   -f                    When set, it look in the file instead of the loaded module")
    imm.log(" ex: !findpacker -m notepad")
    imm.log("NOTE: It might take some times due to the amount of signature on our db")

def main(args):
    imm = immlib.Debugger()
    if not args:
        usage(imm)
        return "No args"
    try:
        opts, argo = getopt.getopt(args, "m:f")
    except getopt.GetoptError:
        usage(imm)
        return "Bad heap argument %s" % args[0]

    module = None
    OnMemory = 1
    
    for o,a in opts:
        if o == "-m":
            module = a
        elif o == '-f':
            OnMemory = 0
            
    if not module:
        usage(imm)
        return "No module provided, see the Log Window for details of usage"
    
    try:
        ret = imm.findPacker( module, OnMemory = OnMemory)
    except Exception, msg:
        return "Error: %s" % msg
    
    if not ret:
        return "No Packer found"
    
    for (addr, name) in ret:
        imm.log("Packer found!: %s at 0x%08x" % (name, addr), address = addr)
    return "Packers found on %s: %d" % (module, len(ret))
