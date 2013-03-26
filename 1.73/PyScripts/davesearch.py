#!/usr/bin/env python
"""
Finder for dave

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} 

"""

__VERSION__ = '1.0'
import immlib
from immutils import *
def main(): 
    imm = immlib.Debugger()
    result = []
    #opcode = ["jmp eax", "call eax", "push eax\nret", "pop ebp\nret"]
    opcode = ["pop rA\npop rB\nret"]
    for op in opcode:        
        
        addys= imm.searchCommands(op)
        for ad in addys:
            #imm.Log( str(ad) )
            result += imm.searchLong( ad[0] )
            
        for a in result:
            imm.Log("Found! %s" % op, address=a )
        
if __name__=="__main__":
    print "This module is for use within Immunity Debugger only"