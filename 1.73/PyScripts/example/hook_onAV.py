#!/usr/bin/env python
"""
Example of using hook class
Place a hook on Access Violation
Get hook.run() executed when hook occurs

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} 

"""

__VERSION__ = '1.0'

import immlib
from immlib import AccessViolationHook



class MyOwnHook(AccessViolationHook):
    def __init__(self):
        AccessViolationHook.__init__(self)
        
    def run(self):
        """This will be executed when hooktype happens"""
        imm = immlib.Debugger()
        regs=imm.getRegs()
        disassembled=imm.disasm(regs["EIP"])
        imm.Log("EIP on ACCESS_VIOLATION %s" % str(regs["EIP"]))
        imm.Log("Disassembled command: %s" % disassembled.result)
                
        
    
    

def main(): 
    imm = immlib.Debugger()
    #lets force an access violation for test porpouses
    imm.setReg("ESP",0xFFFFFFFF)
    
    hook = MyOwnHook()
    hook.add("hookonaccessviolation")
    imm.Error("Python script finishes here\n\
Hook stays at debugger core\n\
Hook will execute on %s" % hooktype)
    

if __name__=="__main__":
    print "This module is for use within Immunity Debugger only"

    
    