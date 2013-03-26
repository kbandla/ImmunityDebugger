#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}
"""


__VERSION__ = '1.0'
import immlib

DESC = "Search code in memory"

def usage(imm):
    imm.Log("!searchcode  Search code in memory")
    imm.Log("!searchcode  <asm code>")

def main(args):
    imm = immlib.Debugger()

    look = " ".join(args)
    ret = imm.Search( imm.Assemble( look ) )

    for a in ret:

        module = imm.findModule(a)
        if not module:
            module = "none"
        else:
            module = module[0]
        
        # Grab the memory access type for this address
        page   = imm.getMemoryPagebyAddress( a )
        access = page.getAccess( human = True )
        
        imm.Log("Found %s at 0x%08x [%s] Access: (%s)" % (look, a, module, access), address = a)
    if ret:
        return "Found %d address (Check the Log Windows for details)" % len(ret)
    else:
        return "Sorry, no code found"
