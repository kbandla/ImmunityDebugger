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

def main(args):
    imm = immlib.Debugger()
    address = 0x0
    file = None
    try:
        opts, argo = getopt.getopt(args, "a:f:")
    except getopt.GetoptError:
        imm.setStatusBar("Usage: !cmpmem -a ADDRESS -f FILETOCMP" % str(args))
        return 0

    for o,a in opts:
        if o == "-a":
            try:
                address = int(a, 16)
            except ValueError, msg:
                
                imm.setStatusBar( "Invalid heap address: %s" % a )
                return 0
        if o == "-f":
            try:
                file = a
            except ValueError, msg:
                imm.setStatusBar( "Invalid heap address: %s" % a )
                return 0

    if file and address:
        lines = open(file).readlines()
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
                    imm.setStatusBar("Unmatched: Check log window for the dump")
                    imm.Log("Unmatched at offset: %d" % a)
                    imm.Log("  File: %s" % immutils.prettyhexprint( string.joinfields(fmem[ a: a + 8 ], "") ) )
                    imm.Log("  Mem : %s" % immutils.prettyhexprint(  mem[ a: a + 8 ] ) )
                    return 0x0
            except IndexError:
                imm.setStatusBar("Unmatched: Check log window for the dump")
                imm.Log("Unmatch: Different string sizes= File: %d Memory: %d" % (len(fmem), len(mem)) )
                return 0x0
                 
        imm.setStatusBar("Match!")
        imm.Log("Match!")
    return 0 