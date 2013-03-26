#!/usr/bin/env python
"""
pe_export.py  - a module for Immunity Debugger that exports 

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} 

"""

__VERSION__ = '1.0'

import sys
if "Libs" not in sys.path:
    sys.path.append("Libs")
if "." not in sys.path: sys.path.append(".")
import pelib

#These imports won't work except from ImmDBG
import immlib
from immutils import *

def main(): 
    imm = immlib.Debugger()
    allmodules=imm.getAllModules()
    for key in allmodules.keys():
        imm.Log("Found module: %s"%key)
    usekey=""
    for key in allmodules.keys():
        if key.count(".exe"):
            imm.Log("Found executable to dump %s"%key)
            usekey=key
            break
    module_to_dump=allmodules[key]
    base=module_to_dump.getCodebase()
    size=module_to_dump.getCodesize()
    codememory=imm.readMemory(base,size)
    
if __name__=="__main__":
    print "This module is for use within Immunity Debugger only"
    