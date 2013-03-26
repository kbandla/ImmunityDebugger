#!/usr/bin/env python
"""
Disassembling back and forward example

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} 

"""

__VERSION__ = '1.0'

import immlib

def main():
    imm=immlib.Debugger()
    nlines=10 #number of lines to go backward and forward

    address=0x01007403 # be sure to use your own address here
    
    opcode=imm.disasmBackward(address,nlines)
    imm.Log("%d lines backward original %d address is:  %s" % (nlines,address,opcode.result))

    opcode=imm.disasmForward(address,nlines)
    imm.Log("%d lines forward original %d address is:  %s" % (nlines,address,opcode.result))
    
if __name__=="__main__":
    print "This module is for use within Immunity Debugger only"    
                            
