#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}
"""


__VERSION__ = '1.0'

import immlib
import getopt
from libheap import *

DESC = "Search the heap for specific chunks"

def usage(imm):
    imm.log("!searchheap  Search the heap for specific chunks")
    imm.log("!searchheap  [-h HEAP_ADDR] [-s] [-r] [-f] [-c]")
    imm.log("   -h HEAPADDR    Set the heap address to inspect")
    imm.log("   -w what        What to search for: size, prevsize, flags, address, next, prev")
    imm.log("   -a action      Search action: =, !=, >, <, >=, <=, &, not")
    imm.log("   -v value       Value to be searched")
    imm.log("   -k             Show the content of the chunk")
    imm.log("   -r             Use the restored heap (see !heap for more details)")
    
    
def main(args):
    imm = immlib.Debugger()
    imm.log("### Immunity's Search Heap ###")  

    try:
        opts, argo = getopt.getopt(args, "h:w:a:v:rk", ["heap=", "what=", "action=", "value="])
    except getopt.GetoptError:
        imm.setStatusBar("Bad heap argument %s" % args[0])
        usage(imm)
        return 0

    heap   = 0x0
    what   = None
    action = None
    value  = None
    restore = False
    chunkdisplay = 0

    for o,a in opts:
        if o == "-h":
            try:
                heap = int(a, 16)
            except ValueError, msg:
                imm.InfoLine("Invalid heap address: %s" % a)
                return 0
        elif o == "-r":
            restore = True
        elif o == "-k":
            chunkdisplay = SHOWCHUNK_FULL
        elif o in ("-w", "--what"):
            what = a
        elif o in ("-a", "--action"):
            action = a
        elif o in ("-v", "--value"):
            try:
                value = int(a, 16)
            except ValueError, msg:
                return "Invalid value: %s" % a
                return 0
            
    if not heap or ( heap in imm.getHeapsAddress() ):
        s = SearchHeap(imm, what, action, value, heap = heap, restore = restore, option = chunkdisplay)
        if heap:
            return "Heap 0x%x dumped" % heap    
        else:
            return "Heap dumped"
    return "Wrong Heap"