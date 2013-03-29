#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007

U{Immunity Inc.<http://www.immunityinc.com>}
"""

import immlib
from libheap import *
import getopt, string
import immutils

DESC = "Compare memory with a file (file been a dump from prettyhexprint)"
NAME = "cmpmemp"

def usage(imm):
    imm.log("!%s    -a ADDR -f FILE_PATH" % NAME)
    imm.log("%s" % DESC)

def main(args):
    imm = immlib.Debugger()
    address = 0x0
    f_name = None
    try:
        opts, argo = getopt.getopt(args, "a:f:")
    except getopt.GetoptError:
        return "Usage: !cmpmem -a ADDRESS -f FILETOCMP" % str(args)

    for o,a in opts:
        if o == "-a":
            try:
                address = int(a, 16)
            except ValueError, msg:
                return "Invalid heap address: %s" % a
        elif o == "-f":
                f_name = a

    if f_name and address:
        lines = open(f_name).readlines()
        fmem = []
        for line in lines:
            line = line.strip().split(" ")
            for number in line:
                try: 
                    fmem.append( chr( int(number, 16) ) )
                except ValueError:
                    continue
        fmem = fmem
        mem  = imm.readMemory(address, len(fmem) )
        for a in range(0, len(fmem)):
            try:
                if fmem[a] != mem[a]:
                    imm.log("Unmatched at offset: %d" % a)
                    imm.log("  File: %s" % immutils.prettyhexprint( string.joinfields(fmem[ a: a + 8 ], "") ) )
                    imm.log("  Mem : %s" % immutils.prettyhexprint(  mem[ a: a + 8 ] ) )
                    return "Unmatched: Check log window for the dump"
            except IndexError:
                log_str = "Unmatch: Different string sizes= File: %d Memory: %d" % (len(fmem), len(mem))
                imm.log("%s" % log_str)
                return log_str
                 
        imm.log("Match!")
        return "Match!"

    return "No match"
