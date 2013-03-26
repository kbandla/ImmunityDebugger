#!/usr/bin/env python
"""
Custom table example

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} 

"""

__VERSION__ = '1.0'

import immlib
from immutils import *
def main(): 
    imm = immlib.Debugger()
    #create a table, with 2 max columns: Module and Path
    table=imm.createTable("Custom table: Modules list",["Module","Path"])
    #get all loaded modules
    allmodules=imm.getAllModules()
    for key in allmodules.keys():
        path=str(allmodules[key].getPath())
        #add them to table, first arg can be a related address to the row, so clicking into the row will pop
        #up asm window at the related address
        table.add(None,[key,path])
    
if __name__=="__main__":
    print "This module is for use within Immunity Debugger only" 
        
