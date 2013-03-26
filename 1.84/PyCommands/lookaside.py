#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}
"""

__VERSION__ = '1.0'

DESC = """Shows the Lookaside of the Heap structure"""

import immlib
from libheap import *
import getopt
import libdatatype

def usage(imm):
    imm.log("!lookaside     Shows the Lookaside of the Heap structure")
    imm.log("-h             Heap Address", focus=1)
    imm.log("-d             Discovery DataType")

def main(args):
    imm = immlib.Debugger()
    heap = 0x0
    discover = None

    if not args:
        usage(imm)
        return "Wrong args (Check the Log Window)"
        
    try:
        opts, argo = getopt.getopt(args, "h:d")
    except getopt.GetoptError:
        usage(imm)
        return "Bad heap argument %s" % args[0]

    for o,a in opts:
        if o == "-h":
            try:
                heap = int(a, 16)
            except ValueError, msg:
                self.InfoLine("Invalid heap address: %s" % a)
                return 0
	elif o == '-d':
            discover = libdatatype.DataTypes(imm)		

    if heap:
        pheap = PHeap( imm, heap )
        lookaddr = pheap.Lookaddr
        imm.log("Dumping Lookaside: 0x%08x  (0x%08x) " % (lookaddr, heap) )        
        if lookaddr:
            plook = PHeapLookaside( imm, lookaddr )
    
            for ndx in range(0, len(plook) ):
                l = plook[ndx]
                if not l.isEmpty():
                    imm.log("Lookaside[%02x]:  " % ndx, address = l.addr)
                    for a in l.getList():
                        imm.log(" " * 15 +"> 0x%08x  (%d)" % (a, ndx * 8), address = a, focus=1)   
                        if discover:
                            list = discover.Get( a+4, ndx*8 - 4)
			    for obj in list:
                                imm.log(" " * 15 + "[%s] %s" %  (obj.name, obj.Print()), address = obj.address ) 
                
        return "Lookaside at 0x%08x dumped" % lookaddr
    else:
        usage(imm)
        return "No Heap Provided"
