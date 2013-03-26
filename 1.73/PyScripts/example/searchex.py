#!/usr/bin/env python
"""
search in one module and in all modules example

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} 

"""

__VERSION__ = '1.0'

import immlib

def main():
    imm = immlib.Debugger()
    cmd="pop ebx"
    res=imm.searchCommandsOnModule(0x7C9C1005,cmd)
    imm.Log("one module")
    for addy in res:
        imm.Log( str(addy))
    res=imm.searchCommands(cmd)
    imm.Log("all modules")
    for addy in res:
        imm.Log( str(addy) )
    

if __name__=="__main__":
    print "This module is for use within Immunity Debugger only"